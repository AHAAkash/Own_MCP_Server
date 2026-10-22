from __future__ import annotations

import asyncio
import time
from pathlib import Path

import jwt
import pytest
from starlette.types import Message, Receive, Scope, Send

from mcp_advanced.config import Settings
from mcp_advanced.server import _read_file
from mcp_advanced.security import (
    Principal,
    SecurityError,
    TenantSessionOwnershipMiddleware,
    TenantTokenVerifier,
    TokenBucketLimiter,
    issue_token,
    require_scope,
    resolve_in_roots,
    resolve_tenant_roots,
)


def test_token_verifier_scopes_and_tenant_claims() -> None:
    settings = Settings(jwt_secret="s" * 40, jwt_ttl_seconds=300)
    token = issue_token(settings, "tenant-a", "user-a", ["mcp:tools", "files:read"], ["src"])
    result = asyncio.run(TenantTokenVerifier(settings).verify_token(token))
    assert result is not None
    assert result.subject == "user-a"
    assert result.claims is not None
    assert result.claims["tenant_id"] == "tenant-a"
    assert result.scopes == ["files:read", "mcp:tools"]
    with pytest.raises(SecurityError, match="sampling:request"):
        require_scope(Principal("tenant-a", "user-a", frozenset(result.scopes), ("src",)), "sampling:request")


def test_expired_token_is_rejected() -> None:
    settings = Settings(jwt_secret="s" * 40)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": "user",
            "tenant_id": "tenant",
            "scope": "mcp:tools",
            "iat": now - 120,
            "exp": now - 1,
        },
        settings.jwt_secret or "",
        algorithm="HS256",
    )
    assert asyncio.run(TenantTokenVerifier(settings).verify_token(token)) is None


def test_path_sandbox_blocks_traversal_and_absolute_escape(tmp_path: Path) -> None:
    root = tmp_path / "tenant" / "src"
    root.mkdir(parents=True)
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(SecurityError, match="traversal"):
        resolve_in_roots("../secret.txt", [root])
    with pytest.raises(SecurityError, match="outside"):
        resolve_in_roots(str(outside), [root])


def test_path_sandbox_rejects_symlink(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this platform")
    with pytest.raises(SecurityError, match="Symbolic links"):
        resolve_in_roots("link.txt", [root])


def test_roots_are_isolated_per_tenant_user(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data")
    first = resolve_tenant_roots(
        settings, Principal("tenant-a", "user-a", frozenset({"files:read"}), ("src",)), stdio=False
    )[0]
    second = resolve_tenant_roots(
        settings, Principal("tenant-a", "user-b", frozenset({"files:read"}), ("src",)), stdio=False
    )[0]
    first_file = first / "value.txt"
    first_file.write_text("one", encoding="utf-8")
    assert first != second
    assert not (second / "value.txt").exists()


def test_rate_limiter_rejects_excess_requests() -> None:
    limiter = TokenBucketLimiter(capacity=1, refill_per_second=0.001)
    limiter.check("tenant:user")
    with pytest.raises(SecurityError, match="rate limit"):
        limiter.check("tenant:user")


def test_http_configuration_requires_a_strong_signing_key() -> None:
    with pytest.raises(ValueError, match="MCP_JWT_SECRET"):
        Settings().validate(http=True)
    with pytest.raises(ValueError, match="MCP_JWT_TTL_SECONDS"):
        Settings(jwt_secret="s" * 40, jwt_ttl_seconds=86_400).validate(http=True)


def test_token_issuer_rejects_traversal_roots() -> None:
    with pytest.raises(SecurityError, match="invalid_root"):
        issue_token(Settings(jwt_secret="s" * 40), "tenant-a", "user-a", ["mcp:tools"], ["../other"])


def test_file_read_is_size_bounded(tmp_path: Path) -> None:
    target = tmp_path / "content.txt"
    target.write_bytes(b"123456")
    assert _read_file(target, 6) == "123456"
    with pytest.raises(ValueError, match="file_too_large"):
        _read_file(target, 5)


def test_stateful_session_is_bound_to_its_tenant() -> None:
    settings = Settings(jwt_secret="s" * 40)
    token_a = issue_token(settings, "tenant-a", "user-a", ["mcp:tools"], [])
    token_b = issue_token(settings, "tenant-b", "user-b", ["mcp:tools"], [])
    calls = 0

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal calls
        calls += 1
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"mcp-session-id", b"session-a")],
        })
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = TenantSessionOwnershipMiddleware(app, settings)

    async def send_request(token: str, session_id: str | None = None) -> list[Message]:
        headers = [(b"authorization", f"Bearer {token}".encode())]
        if session_id:
            headers.append((b"mcp-session-id", session_id.encode()))
        scope = {"type": "http", "path": "/mcp", "method": "POST", "headers": headers}
        messages: list[Message] = []

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Message) -> None:
            messages.append(message)

        await middleware(scope, receive, send)
        return messages

    first = asyncio.run(send_request(token_a))
    assert next(message["status"] for message in first if message["type"] == "http.response.start") == 200
    denied = asyncio.run(send_request(token_b, "session-a"))
    assert next(message["status"] for message in denied if message["type"] == "http.response.start") == 403
    assert b"session_tenant_mismatch" in next(
        message["body"] for message in denied if message["type"] == "http.response.body"
    )
    assert calls == 1
