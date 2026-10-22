"""FastMCP tool registration and authenticated transport configuration."""
from __future__ import annotations

import argparse
import asyncio
import fnmatch
import os
import time
from dataclasses import replace
from pathlib import Path

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.types import SamplingMessage, TextContent
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from .config import Settings
from .observability import LOGGER, METRICS, tool_span
from .observability import TelemetryMiddleware
from .security import (
    SecurityError,
    TenantTokenVerifier,
    TenantSessionOwnershipMiddleware,
    TokenBucketLimiter,
    Principal,
    principal_for_request,
    require_scope,
    resolve_in_roots,
    resolve_tenant_roots,
)


class ScanLimitExceeded(Exception):
    pass


def _walk_files(roots: list[Path], pattern: str, limit: int, max_scanned: int) -> list[Path]:
    found: list[Path] = []
    ignored = {".git", ".venv", "__pycache__", ".mcp-data"}
    scanned = 0
    visited_directories = 0

    def raise_walk_error(error: OSError) -> None:
        raise error

    for root in roots:
        for current, dirs, files in os.walk(root, followlinks=False, onerror=raise_walk_error):
            visited_directories += 1
            if visited_directories > max_scanned:
                raise ScanLimitExceeded(f"directory scan exceeded {max_scanned} entries")
            dirs[:] = sorted(
                directory for directory in dirs
                if directory not in ignored and not (Path(current) / directory).is_symlink()
            )[:max_scanned]
            for filename in sorted(files):
                scanned += 1
                if scanned > max_scanned:
                    raise ScanLimitExceeded(f"file scan exceeded {max_scanned} entries")
                candidate = Path(current) / filename
                if candidate.is_symlink() or not fnmatch.fnmatch(candidate.name, pattern):
                    continue
                found.append(candidate)
                if len(found) >= limit:
                    return found
    return found


def build_server(
    host: str | None = None,
    port: int | None = None,
    stateless: bool | None = None,
    json_response: bool | None = None,
    *,
    settings: Settings | None = None,
    http: bool = False,
) -> FastMCP:
    config = settings or Settings.from_env()
    if host is not None:
        config = replace(config, host=host)
    if port is not None:
        config = replace(config, port=port)
    if stateless is not None:
        config = replace(config, stateless_http=stateless)
    if json_response is not None:
        config = replace(config, json_response=json_response)
    config.validate(http=http)

    verifier = TenantTokenVerifier(config) if http else None
    auth = (
        AuthSettings.model_validate({
            "issuer_url": config.jwt_issuer,
            "required_scopes": ["mcp:tools"],
            "resource_server_url": None,
        })
        if http else None
    )
    mcp = FastMCP(
        config.app_name,
        host=config.host,
        port=config.port,
        stateless_http=config.stateless_http,
        json_response=config.json_response,
        session_idle_timeout=config.session_idle_timeout_seconds,
        max_sessions=config.max_sessions,
        token_verifier=verifier,
        auth=auth,
    )
    limiter = TokenBucketLimiter(config.rate_limit, config.rate_limit / 60)

    def authorize(ctx: Context, name: str, scope: str) -> tuple[Principal, list[Path]]:
        principal = principal_for_request(stdio_root=config.demo_root if not http else None)
        require_scope(principal, scope)
        limiter.check(principal.key)
        METRICS.increment("tool_authorized", name)
        LOGGER.info(
            "Tool invocation authorized",
            extra={"event": "tool_call", "tenant_id": principal.tenant_id,
                   "user_id": principal.user_id, "tool": name},
        )
        return principal, resolve_tenant_roots(config, principal, stdio=not http)

    async def sample(
        ctx: Context, principal: Principal, prompt: str, max_tokens: int = 500,
        system: str | None = None,
    ) -> str:
        require_scope(principal, "sampling:request")
        if config.stateless_http:
            raise SecurityError(
                "sampling_unavailable",
                "MCP sampling requires stateful Streamable HTTP sessions",
                status_code=409,
            )
        started = time.perf_counter()
        METRICS.increment("sampling_requests", "started")
        LOGGER.info("Sampling requested", extra={
            "event": "sampling_request", "tenant_id": principal.tenant_id,
            "user_id": principal.user_id, "tool": "sampling",
        })
        try:
            async with tool_span("sampling", principal.tenant_id):
                result = await asyncio.wait_for(
                    ctx.session.create_message(
                        messages=[SamplingMessage(role="user", content=TextContent(type="text", text=prompt))],
                        max_tokens=max_tokens,
                        system_prompt=system,
                    ),
                    timeout=config.request_timeout_seconds,
                )
            METRICS.increment("sampling_requests", "success")
            return result.content.text if result.content.type == "text" else ""
        except Exception as exc:
            METRICS.increment("sampling_requests", "failure")
            LOGGER.exception(
                "Sampling request failed",
                extra={"event": "sampling_failure", "tenant_id": principal.tenant_id,
                       "user_id": principal.user_id, "tool": "sampling"},
            )
            raise ToolError(f"sampling_failed: {type(exc).__name__}") from exc
        finally:
            METRICS.observe("sampling", time.perf_counter() - started)

    def record_file_access(principal: Principal, name: str, path: str, status: str) -> None:
        LOGGER.info(
            "Workspace file access",
            extra={"event": "file_access", "tenant_id": principal.tenant_id,
                   "user_id": principal.user_id, "tool": name,
                   "code": status, "resource": path},
        )

    @mcp.tool()
    async def summarize_text(text: str, ctx: Context, max_words: int = 80) -> str:
        """Summarize text using the client's language model (MCP sampling)."""
        principal, _ = authorize(ctx, "summarize_text", "sampling:request")
        if not text.strip() or len(text) > 100_000 or not 1 <= max_words <= 500:
            raise ToolError("invalid_input: text must be 1..100000 characters and max_words 1..500")
        async with tool_span("summarize_text", principal.tenant_id):
            await ctx.info("Requesting summary from client LLM via sampling...")
            return await sample(
                ctx, principal,
                f"Summarize the following in at most {max_words} words:\n\n{text}",
                system="You are a precise summarizer.",
            )

    @mcp.tool()
    async def review_file(path: str, ctx: Context) -> str:
        """Read a file from a tenant workspace, then have the client's LLM review it."""
        principal, roots = authorize(ctx, "review_file", "files:read")
        require_scope(principal, "sampling:request")
        try:
            target = resolve_in_roots(path, roots)
            content = await asyncio.wait_for(
                asyncio.to_thread(_read_file, target, config.max_file_bytes),
                timeout=config.request_timeout_seconds,
            )
        except Exception:
            record_file_access(principal, "review_file", path, "denied_or_failed")
            raise
        record_file_access(principal, "review_file", path, "allowed")
        async with tool_span("review_file", principal.tenant_id):
            return await sample(
                ctx, principal,
                f"Review this file ({target.name}). List bugs, risks, and improvements:\n\n{content}",
                max_tokens=800,
            )

    @mcp.tool()
    async def long_running_task(ctx: Context, steps: int = 5, delay: float = 1.0) -> str:
        """Simulate bounded work and stream log + progress notifications."""
        principal, _ = authorize(ctx, "long_running_task", "mcp:tools")
        if not 1 <= steps <= 100 or not 0 <= delay <= 5:
            raise ToolError("invalid_input: steps must be 1..100 and delay 0..5 seconds")
        async with tool_span("long_running_task", principal.tenant_id):
            await ctx.info(f"Starting task with {steps} steps")
            for i in range(1, steps + 1):
                await asyncio.sleep(delay)
                await ctx.debug(f"Working on step {i}")
                try:
                    await ctx.report_progress(progress=i, total=steps, message=f"Step {i}/{steps}")
                except Exception:
                    METRICS.increment("progress_notification_drops", "long_running_task")
                    LOGGER.warning("Progress notification delivery failed", extra={
                        "event": "progress_drop", "tenant_id": principal.tenant_id,
                        "user_id": principal.user_id, "tool": "long_running_task",
                    })
                if i == steps // 2:
                    await ctx.warning("Halfway there")
            await ctx.info("Task complete")
            return f"Completed {steps} steps"

    @mcp.tool()
    async def list_root_files(ctx: Context, pattern: str = "*", max_results: int = 100) -> list[str]:
        """List non-symlink files under tenant-granted workspace roots."""
        principal, roots = authorize(ctx, "list_root_files", "files:read")
        _validate_pattern(pattern)
        if not 1 <= max_results <= config.max_results:
            raise ToolError(f"invalid_input: max_results must be 1..{config.max_results}")
        async with tool_span("list_root_files", principal.tenant_id):
            try:
                paths = await asyncio.wait_for(
                    asyncio.to_thread(
                        _walk_files, roots, pattern, max_results, config.max_search_files
                    ),
                    timeout=config.request_timeout_seconds,
                )
            except ScanLimitExceeded as exc:
                raise ToolError(f"scan_limit_exceeded: {exc}") from exc
            return [str(path) for path in paths]

    @mcp.tool()
    async def read_root_file(path: str, ctx: Context) -> str:
        """Read a text file, only if it lies inside a tenant-granted workspace root."""
        principal, roots = authorize(ctx, "read_root_file", "files:read")
        try:
            target = resolve_in_roots(path, roots)
            async with tool_span("read_root_file", principal.tenant_id):
                content = await asyncio.wait_for(
                    asyncio.to_thread(_read_file, target, config.max_file_bytes),
                    timeout=config.request_timeout_seconds,
                )
            record_file_access(principal, "read_root_file", path, "allowed")
            return content
        except Exception:
            record_file_access(principal, "read_root_file", path, "denied_or_failed")
            raise

    @mcp.tool()
    async def search_in_roots(
        query: str, ctx: Context, glob: str = "*.py", max_hits: int = 50
    ) -> list[str]:
        """Search bounded, non-symlink files in tenant-granted workspace roots."""
        principal, roots = authorize(ctx, "search_in_roots", "files:read")
        _validate_pattern(glob)
        if not query or len(query) > 500 or not 1 <= max_hits <= config.max_results:
            raise ToolError("invalid_input: query must be 1..500 characters and max_hits within configured limit")
        async with tool_span("search_in_roots", principal.tenant_id):
            try:
                files = await asyncio.wait_for(
                    asyncio.to_thread(
                        _walk_files, roots, glob, config.max_search_files, config.max_search_files
                    ),
                    timeout=config.request_timeout_seconds,
                )
            except ScanLimitExceeded as exc:
                raise ToolError(f"scan_limit_exceeded: {exc}") from exc
            hits: list[str] = []
            for index, file_path in enumerate(files, 1):
                try:
                    content = await asyncio.wait_for(
                        asyncio.to_thread(_read_file, file_path, config.max_file_bytes),
                        timeout=config.request_timeout_seconds,
                    )
                except (OSError, ValueError):
                    record_file_access(principal, "search_in_roots", str(file_path), "denied_or_failed")
                    continue
                record_file_access(principal, "search_in_roots", str(file_path), "allowed")
                for line_number, line in enumerate(content.splitlines(), 1):
                    if query.casefold() in line.casefold():
                        hits.append(f"{file_path}:{line_number}: {line.strip()[:1_000]}")
                        if len(hits) >= max_hits:
                            return hits
                try:
                    await ctx.report_progress(index, len(files), f"Scanned {file_path.name}")
                except Exception:
                    METRICS.increment("progress_notification_drops", "search_in_roots")
            return hits

    @mcp.tool()
    async def server_info(ctx: Context) -> dict:
        """Report transport configuration and negotiated client capabilities."""
        principal, _ = authorize(ctx, "server_info", "mcp:tools")
        caps = ctx.session.client_params.capabilities if ctx.session.client_params else None
        return {
            "stateless_http": config.stateless_http,
            "json_response": config.json_response,
            "authenticated": bool(get_access_token()),
            "tenant_id": principal.tenant_id,
            "client_supports_sampling": bool(caps and caps.sampling),
            "client_supports_roots": bool(caps and caps.roots),
        }

    @mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": config.app_name})

    @mcp.custom_route("/ready", methods=["GET"], include_in_schema=False)
    async def readiness(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ready", "service": config.app_name})

    @mcp.custom_route("/metrics", methods=["GET"], include_in_schema=False)
    async def metrics(_request: Request) -> PlainTextResponse:
        return PlainTextResponse(METRICS.render_prometheus(), media_type="text/plain; version=0.0.4")

    return mcp


def _read_file(path: Path, max_bytes: int) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as file:
        content = file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError(f"file_too_large: maximum allowed size is {max_bytes} bytes")
    return content.decode("utf-8", errors="replace")


def _validate_pattern(pattern: str) -> None:
    if not pattern or len(pattern) > 128 or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
        raise ToolError("invalid_input: pattern must be a bounded relative glob")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--stateless", action="store_true", default=None)
    parser.add_argument("--json-response", action="store_true", default=None)
    args = parser.parse_args()
    server = build_server(
        host=args.host, port=args.port, stateless=args.stateless,
        json_response=args.json_response, http=args.transport == "http",
    )
    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        import uvicorn

        app = server.streamable_http_app()
        app.add_middleware(TelemetryMiddleware)
        app.add_middleware(
            TenantSessionOwnershipMiddleware,
            settings=Settings.from_env(),
            mcp_path=server.settings.streamable_http_path,
        )
        uvicorn.run(app, host=server.settings.host, port=server.settings.port, log_config=None)


if __name__ == "__main__":
    main()
