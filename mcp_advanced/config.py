"""Typed process configuration with fail-fast parsing."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized not in {"1", "true", "yes", "0", "false", "no"}:
        raise ValueError(f"{name} must be true or false")
    return normalized in {"1", "true", "yes"}


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = "advanced-mcp-server"
    host: str = "127.0.0.1"
    port: int = 8000
    jwt_secret: str | None = None
    jwt_issuer: str = "https://auth.local.invalid"
    jwt_audience: str = "advanced-mcp"
    jwt_ttl_seconds: int = 900
    data_dir: Path = Path(".mcp-data")
    demo_root: Path = Path(".")
    max_file_bytes: int = 200_000
    max_search_files: int = 500
    max_results: int = 100
    rate_limit: int = 60
    request_timeout_seconds: float = 20.0
    session_idle_timeout_seconds: float = 1800.0
    max_sessions: int = 10_000
    stateless_http: bool = False
    json_response: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        try:
            return cls(
                host=os.getenv("MCP_HOST", "127.0.0.1"),
                port=int(os.getenv("MCP_PORT", "8000")),
                jwt_secret=os.getenv("MCP_JWT_SECRET"),
                jwt_issuer=os.getenv("MCP_JWT_ISSUER", "https://auth.local.invalid"),
                jwt_audience=os.getenv("MCP_JWT_AUDIENCE", "advanced-mcp"),
                jwt_ttl_seconds=int(os.getenv("MCP_JWT_TTL_SECONDS", "900")),
                data_dir=Path(os.getenv("MCP_DATA_DIR", ".mcp-data")).resolve(),
                demo_root=Path(os.getenv("MCP_ROOT", Path(__file__).resolve().parent.parent)).resolve(),
                max_file_bytes=int(os.getenv("MCP_MAX_FILE_BYTES", "200000")),
                max_search_files=int(os.getenv("MCP_MAX_SEARCH_FILES", "500")),
                max_results=int(os.getenv("MCP_MAX_RESULTS", "100")),
                rate_limit=int(os.getenv("MCP_RATE_LIMIT_PER_MINUTE", "60")),
                request_timeout_seconds=float(os.getenv("MCP_REQUEST_TIMEOUT_SECONDS", "20")),
                session_idle_timeout_seconds=float(os.getenv("MCP_SESSION_IDLE_TIMEOUT_SECONDS", "1800")),
                max_sessions=int(os.getenv("MCP_MAX_SESSIONS", "10000")),
                stateless_http=_bool("MCP_STATELESS_HTTP", False),
                json_response=_bool("MCP_JSON_RESPONSE", False),
            )
        except ValueError as exc:
            raise ValueError(f"Invalid MCP configuration: {exc}") from exc

    def validate(self, *, http: bool) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("MCP_PORT must be between 1 and 65535")
        if not 60 <= self.jwt_ttl_seconds <= 3600:
            raise ValueError("MCP_JWT_TTL_SECONDS must be between 60 and 3600")
        if (
            not 1 <= self.max_file_bytes <= 10_000_000
            or not 1 <= self.max_search_files <= 10_000
            or not 1 <= self.max_results <= 1_000
        ):
            raise ValueError("File and result limits exceed safe configured bounds")
        if not 1 <= self.rate_limit <= 10_000 or not 0 < self.request_timeout_seconds <= 300:
            raise ValueError("Rate limit and request timeout must be positive")
        if not 60 <= self.session_idle_timeout_seconds <= 86_400 or not 1 <= self.max_sessions <= 100_000:
            raise ValueError("Session idle timeout and maximum sessions are outside safe bounds")
        if http and (not self.jwt_secret or len(self.jwt_secret.encode()) < 32):
            raise ValueError("HTTP mode requires MCP_JWT_SECRET with at least 32 characters")
