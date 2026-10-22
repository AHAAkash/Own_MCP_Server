"""Tenant tokens, tool authorization, and strict filesystem confinement."""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.middleware.auth_context import get_access_token
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Settings

_TENANT_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9:_-]{0,63}$")


class SecurityError(Exception):
    """Expected authentication, authorization, or sandbox rejection."""

    def __init__(self, code: str, message: str, status_code: int = 403):
        super().__init__(message)
        self.code = code
        self.status_code = status_code

    def __str__(self) -> str:
        return f"{self.code}: {self.args[0]}"


@dataclass(frozen=True, slots=True)
class Principal:
    tenant_id: str
    user_id: str
    scopes: frozenset[str]
    roots: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.tenant_id}:{self.user_id}"


def _safe_component(value: str, label: str) -> str:
    if not _TENANT_PART.fullmatch(value) or value in {".", ".."}:
        raise SecurityError("invalid_identity", f"Invalid {label}")
    return value


def issue_token(
    settings: Settings,
    tenant_id: str,
    user_id: str,
    scopes: list[str],
    roots: list[str],
) -> str:
    settings.validate(http=True)
    secret = settings.jwt_secret
    if secret is None:
        raise ValueError("MCP_JWT_SECRET is required to issue a token")
    tenant = _safe_component(tenant_id, "tenant id")
    user = _safe_component(user_id, "user id")
    if not scopes or len(scopes) > 32 or not all(_SCOPE.fullmatch(scope) for scope in scopes):
        raise SecurityError("invalid_scope", "Scopes must be valid and limited to 32 entries")
    if len(roots) > 32:
        raise SecurityError("invalid_root", "At most 32 workspace roots may be granted")
    clean_roots = [validate_relative_root(root) for root in roots]
    now = int(time.time())
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": user,
        "tenant_id": tenant,
        "scope": " ".join(sorted(set(scopes))),
        "roots": clean_roots,
        "iat": now,
        "exp": now + settings.jwt_ttl_seconds,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def validate_relative_root(root: str) -> str:
    path = Path(root)
    if (
        not root or len(root) > 512 or path.is_absolute() or path.drive
        or any(part in {"..", "."} for part in path.parts)
    ):
        raise SecurityError("invalid_root", "Roots must be non-empty relative paths without traversal")
    normalized = path.as_posix().strip("/")
    if not normalized or normalized.startswith("../"):
        raise SecurityError("invalid_root", "Invalid workspace root")
    return normalized


class TenantTokenVerifier(TokenVerifier):
    def __init__(self, settings: Settings):
        self.settings = settings

    async def verify_token(self, token: str) -> AccessToken | None:
        if not self.settings.jwt_secret:
            return None
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self.settings.jwt_secret,
                algorithms=["HS256"],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id", "scope"]},
            )
            tenant = _safe_component(str(claims["tenant_id"]), "tenant id")
            user = _safe_component(str(claims["sub"]), "user id")
            roots = claims.get("roots", [])
            if not isinstance(roots, list) or len(roots) > 32 or not all(isinstance(root, str) for root in roots):
                return None
            for root in roots:
                validate_relative_root(root)
            raw_scopes = claims.get("scope", "")
            scopes = raw_scopes.split() if isinstance(raw_scopes, str) else []
            if (
                not scopes or len(scopes) > 32
                or not all(isinstance(scope, str) and _SCOPE.fullmatch(scope) for scope in scopes)
            ):
                return None
            claims["tenant_id"] = tenant
            claims["roots"] = roots
            return AccessToken(
                token=token,
                client_id=str(claims.get("client_id", user)),
                scopes=scopes,
                expires_at=int(claims["exp"]),
                subject=user,
                claims=claims,
            )
        except (jwt.InvalidTokenError, KeyError, TypeError, ValueError, SecurityError):
            return None


class TenantSessionOwnershipMiddleware:
    """Bind stateful MCP session IDs to the tenant/user that initialized them."""

    def __init__(self, app: ASGIApp, settings: Settings, mcp_path: str = "/mcp"):
        self.app = app
        self.verifier = TenantTokenVerifier(settings)
        self.mcp_path = mcp_path
        self.idle_timeout = settings.session_idle_timeout_seconds
        self.max_sessions = settings.max_sessions
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != self.mcp_path:
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin1").lower(): value.decode("latin1")
                   for key, value in scope.get("headers", [])}
        authorization = headers.get("authorization", "")
        scheme, _, raw_token = authorization.partition(" ")
        access_token = (
            await self.verifier.verify_token(raw_token)
            if scheme.lower() == "bearer" and raw_token else None
        )
        if access_token is None or not access_token.claims or not access_token.subject:
            await self.app(scope, receive, send)
            return
        principal_key = f"{access_token.claims['tenant_id']}:{access_token.subject}"
        session_id = headers.get("mcp-session-id")
        now = time.monotonic()
        owner_mismatch = False
        at_capacity = False
        if scope.get("method") == "POST" and not session_id:
            with self._lock:
                stale = [
                    current_id for current_id, (_, updated) in self._sessions.items()
                    if now - updated > self.idle_timeout
                ]
                for current_id in stale:
                    del self._sessions[current_id]
                at_capacity = len(self._sessions) >= self.max_sessions
        if at_capacity:
            body = b'{"error":"session_capacity","message":"MCP session capacity reached"}'
            await send({
                "type": "http.response.start",
                "status": 503,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return
        if session_id:
            with self._lock:
                owner = self._sessions.get(session_id)
                if owner and now - owner[1] > self.idle_timeout:
                    del self._sessions[session_id]
                    owner = None
                if owner and owner[0] != principal_key:
                    owner_mismatch = True
                elif owner:
                    self._sessions[session_id] = (principal_key, now)
        if owner_mismatch:
            body = json.dumps({
                "error": "session_tenant_mismatch",
                "message": "MCP session belongs to a different tenant or user",
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return

        async def capture_session(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = {
                    key.decode("latin1").lower(): value.decode("latin1")
                    for key, value in message.get("headers", [])
                }
                created_id = response_headers.get("mcp-session-id")
                if created_id and scope.get("method") == "POST":
                    with self._lock:
                        self._sessions[created_id] = (principal_key, time.monotonic())
                if scope.get("method") == "DELETE" and session_id:
                    with self._lock:
                        self._sessions.pop(session_id, None)
            await send(message)

        await self.app(scope, receive, capture_session)


class TokenBucketLimiter:
    """Process-local per-principal token bucket; use a shared backend when scaling out."""

    def __init__(self, capacity: int, refill_per_second: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            if key not in self._buckets and len(self._buckets) >= 10_000:
                stale = [principal for principal, (_, updated) in self._buckets.items()
                         if now - updated > 120]
                for principal in stale:
                    del self._buckets[principal]
                if len(self._buckets) >= 10_000:
                    raise SecurityError("rate_limiter_capacity", "Rate limiter capacity reached", status_code=503)
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_second)
            if tokens < 1:
                raise SecurityError("rate_limited", "Tool rate limit exceeded", status_code=429)
            self._buckets[key] = (tokens - 1, now)


def principal_for_request(*, stdio_root: Path | None = None) -> Principal:
    token = get_access_token()
    if token and token.claims:
        return Principal(
            tenant_id=str(token.claims["tenant_id"]),
            user_id=str(token.subject),
            scopes=frozenset(token.scopes),
            roots=tuple(token.claims.get("roots", [])),
        )
    if stdio_root is not None:
        return Principal("local", "stdio", frozenset({"*"}), (str(stdio_root),))
    raise SecurityError("unauthenticated", "A valid bearer token is required", status_code=401)


def require_scope(principal: Principal, scope: str) -> None:
    if "*" not in principal.scopes and scope not in principal.scopes:
        raise SecurityError("insufficient_scope", f"Required capability: {scope}")


def resolve_tenant_roots(settings: Settings, principal: Principal, *, stdio: bool) -> list[Path]:
    if stdio:
        return [settings.demo_root.resolve()]
    data_root = settings.data_dir.resolve()
    data_root.mkdir(parents=True, exist_ok=True)
    current = data_root
    for component in ("tenants", principal.tenant_id, principal.user_id, "roots"):
        current = current / component
        if current.is_symlink():
            raise SecurityError("symlink_forbidden", "Symbolic links are not permitted in tenant paths")
        current.mkdir(exist_ok=True)
        current = current.resolve()
        if not current.is_relative_to(data_root):
            raise SecurityError("invalid_root", "Tenant root escaped the configured data directory")
    tenant_root = current
    roots: list[Path] = []
    for relative in principal.roots:
        safe = validate_relative_root(relative)
        root = tenant_root
        for component in Path(safe).parts:
            root = root / component
            if root.is_symlink():
                raise SecurityError("symlink_forbidden", "Symbolic links are not permitted in workspace paths")
            root.mkdir(exist_ok=True)
            root = root.resolve()
            if not root.is_relative_to(tenant_root):
                raise SecurityError("invalid_root", "Workspace root escaped the tenant directory")
        roots.append(root)
    return roots


def resolve_in_roots(requested: str, roots: list[Path]) -> Path:
    if not requested or len(requested) > 4096 or "\x00" in requested:
        raise SecurityError("invalid_path", "A non-empty file path is required")
    path = Path(requested)
    if path.drive and not path.is_absolute():
        raise SecurityError("path_forbidden", "Drive-qualified paths are not allowed")
    if any(part == ".." for part in path.parts):
        raise SecurityError("path_forbidden", "Parent-directory traversal is not allowed")
    candidates = [path] if path.is_absolute() else [root / path for root in roots]
    for candidate in candidates:
        for root in roots:
            try:
                relative = candidate.relative_to(root) if candidate.is_absolute() else candidate
            except ValueError:
                continue
            current = root
            if current.is_symlink():
                continue
            has_symlink = False
            for component in relative.parts:
                current = current / component
                if current.is_symlink():
                    has_symlink = True
                    break
            if has_symlink:
                raise SecurityError("symlink_forbidden", "Symbolic links are not permitted")
            resolved_root = root.resolve()
            resolved = candidate.resolve()
            if resolved == resolved_root or resolved_root in resolved.parents:
                return resolved
    raise SecurityError("path_forbidden", "Path is outside the authorized workspace roots")
