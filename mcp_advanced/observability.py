"""Structured logs, bounded in-memory metrics, and OpenTelemetry spans."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from typing import AsyncIterator

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.trace import Status, StatusCode
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("event", "tenant_id", "user_id", "tool", "code", "resource", "duration_ms"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("mcp_advanced")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = configure_logging()
TRACER = trace.get_tracer("mcp_advanced")

if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "advanced-mcp-server"}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        TRACER = trace.get_tracer("mcp_advanced")
    except ImportError as exc:
        raise RuntimeError(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but OpenTelemetry OTLP dependencies are missing"
        ) from exc


class Metrics:
    def __init__(self) -> None:
        self._counts: Counter[tuple[str, str]] = Counter()
        self._durations: defaultdict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def increment(self, name: str, label: str = "all") -> None:
        with self._lock:
            self._counts[(name, label)] += 1

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            samples = self._durations[name]
            samples.append(seconds)
            if len(samples) > 1000:
                del samples[:len(samples) - 1000]

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# TYPE mcp_events_total counter",
                *(
                    f'mcp_events_total{{event="{name}",label="{label}"}} {value}'
                    for (name, label), value in sorted(self._counts.items())
                ),
                "# TYPE mcp_tool_duration_seconds summary",
            ]
            for name, values in sorted(self._durations.items()):
                safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
                lines.append(f'mcp_tool_duration_seconds_count{{tool="{safe_name}"}} {len(values)}')
                lines.append(f'mcp_tool_duration_seconds_sum{{tool="{safe_name}"}} {sum(values):.6f}')
            return "\n".join(lines) + "\n"


METRICS = Metrics()
_ACTIVE_SESSIONS: dict[str, float] = {}
_SESSION_LOCK = threading.Lock()


class TelemetryMiddleware:
    """Extract W3C trace context and measure HTTP requests and MCP session lifetimes."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin1").lower(): value.decode("latin1")
                   for key, value in scope.get("headers", [])}
        parent_context = propagate.extract(headers)
        context_token = otel_context.attach(parent_context)
        started = time.perf_counter()
        method = scope.get("method", "unknown")
        path = scope.get("path", "unknown")
        session_id = headers.get("mcp-session-id")
        with TRACER.start_as_current_span(f"http.{method.lower()}") as span:
            span.set_attribute("http.request.method", method)
            span.set_attribute("url.path", path)

            async def send_with_session_tracking(message: Message) -> None:
                if message["type"] == "http.response.start":
                    response_headers = {
                        key.decode("latin1").lower(): value.decode("latin1")
                        for key, value in message.get("headers", [])
                    }
                    created_id = response_headers.get("mcp-session-id")
                    if created_id:
                        with _SESSION_LOCK:
                            _ACTIVE_SESSIONS[created_id] = time.perf_counter()
                await send(message)

            try:
                await self.app(scope, receive, send_with_session_tracking)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise
            finally:
                elapsed = time.perf_counter() - started
                span.set_attribute("duration_ms", elapsed * 1000)
                METRICS.observe(f"http_{method.lower()}", elapsed)
                METRICS.increment("http_requests", method.lower())
                if method == "DELETE" and session_id:
                    with _SESSION_LOCK:
                        session_started = _ACTIVE_SESSIONS.pop(session_id, None)
                    if session_started is not None:
                        METRICS.observe("mcp_session", time.perf_counter() - session_started)
                otel_context.detach(context_token)


@asynccontextmanager
async def tool_span(tool: str, tenant_id: str) -> AsyncIterator[None]:
    started = time.perf_counter()
    METRICS.increment("tool_calls", tool)
    with TRACER.start_as_current_span(f"mcp.tool.{tool}") as span:
        span.set_attribute("mcp.tool", tool)
        span.set_attribute("tenant.id", tenant_id)
        try:
            yield
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(trace.Status(trace.StatusCode.ERROR, type(exc).__name__))
            METRICS.increment("tool_errors", tool)
            raise
        finally:
            elapsed = time.perf_counter() - started
            span.set_attribute("duration_ms", elapsed * 1000)
            METRICS.observe(tool, elapsed)
