"""Local web dashboard for watching the MCP client/server demo."""
import argparse
import asyncio
import ipaddress
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from client import make_client_callbacks, run

PROJECT_DIR = Path(__file__).resolve().parent
FRONTEND_FILE = PROJECT_DIR / "frontend" / "index.html"
STATE_LOCK = threading.Lock()


class RunSummary(TypedDict):
    started_at: float
    finished_at: float
    events: int
    status: str


class DashboardState(TypedDict):
    running: bool
    events: list[dict[str, object]]
    runs: list[RunSummary]


class ApprovalResponse(TypedDict):
    approved: bool
    prompt: str


class PendingApproval(TypedDict):
    loop: asyncio.AbstractEventLoop
    event: asyncio.Event
    response: ApprovalResponse | None


STATE: DashboardState = {"running": False, "events": [], "runs": []}
PENDING_APPROVALS: dict[str, PendingApproval] = {}


def publish(event: dict[str, object]) -> None:
    with STATE_LOCK:
        STATE["events"].append(event | {"id": len(STATE["events"]) + 1})


def run_workflow() -> None:
    started_at = time.time()
    try:
        asyncio.run(_run_workflow())
    except Exception as exc:
        publish({"type": "error", "title": "MCP workflow failed", "detail": str(exc)})
    finally:
        with STATE_LOCK:
            STATE["running"] = False
            STATE["runs"].insert(0, {
                "started_at": started_at,
                "finished_at": time.time(),
                "events": len(STATE["events"]),
                "status": "failed" if any(event["type"] == "error" for event in STATE["events"]) else "complete",
            })
            del STATE["runs"][20:]


async def request_sampling_approval(prompt: str) -> str | None:
    request_id = uuid.uuid4().hex
    loop = asyncio.get_running_loop()
    ready = asyncio.Event()
    approval: PendingApproval = {"loop": loop, "event": ready, "response": None}
    with STATE_LOCK:
        PENDING_APPROVALS[request_id] = approval
    publish({
        "type": "approval_required",
        "title": "Sampling approval required",
        "detail": prompt,
        "approval_id": request_id,
    })
    try:
        await asyncio.wait_for(ready.wait(), timeout=120)
        response = approval["response"]
        return response["prompt"] if response and response["approved"] else None
    finally:
        with STATE_LOCK:
            PENDING_APPROVALS.pop(request_id, None)


async def _run_workflow() -> None:
    server_file = PROJECT_DIR / "server.py"
    params = StdioServerParameters(command=sys.executable, args=[str(server_file)])
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            **make_client_callbacks(publish, sampling_approval=request_sampling_approval),
        ) as session:
            await run(session, publish)


class DashboardHandler(BaseHTTPRequestHandler):
    def _local_request_allowed(self) -> bool:
        address = self.server.server_address
        if not isinstance(address, tuple) or len(address) < 2 or not isinstance(address[1], int):
            return False
        port = address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if self.headers.get("Host", "").lower() not in allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.scheme != "http" or parsed.netloc.lower() not in allowed_hosts:
                return False
        return True

    def do_GET(self) -> None:
        if not self._local_request_allowed():
            self.send_error(403, "Local dashboard requests only")
            return
        if self.path == "/api/state":
            with STATE_LOCK:
                body = json.dumps(STATE).encode("utf-8")
            self._send(body, "application/json; charset=utf-8")
            return
        if self.path in ("/", "/index.html"):
            self._send(FRONTEND_FILE.read_bytes(), "text/html; charset=utf-8")
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        if not self._local_request_allowed():
            self.send_error(403, "Local dashboard requests only")
            return
        if self.path.startswith("/api/sampling/"):
            request_id = self.path.removeprefix("/api/sampling/")
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return
            if size > 100_000:
                self.send_error(413, "Approval payload too large")
                return
            try:
                body = json.loads(self.rfile.read(size))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400, "Invalid JSON")
                return
            if not isinstance(body, dict) or not isinstance(body.get("approved"), bool):
                self.send_error(400, "Expected an approved boolean")
                return
            prompt = body.get("prompt", "")
            if not isinstance(prompt, str) or len(prompt) > 100_000:
                self.send_error(400, "Invalid prompt")
                return
            with STATE_LOCK:
                pending = PENDING_APPROVALS.get(request_id)
                if not pending:
                    self._send(b'{"error":"Approval request expired"}', "application/json", 404)
                    return
                pending["response"] = {"approved": body["approved"], "prompt": prompt}
            pending["loop"].call_soon_threadsafe(pending["event"].set)
            self._send(b'{"resolved":true}', "application/json")
            return
        if self.path != "/api/run":
            self.send_error(404, "Not found")
            return
        with STATE_LOCK:
            if STATE["running"]:
                self._send(json.dumps({"error": "A workflow is already running"}).encode(), "application/json", 409)
                return
            STATE["running"] = True
            STATE["events"] = []
        worker = threading.Thread(target=run_workflow, name="mcp-demo", daemon=True)
        worker.start()
        self._send(b'{"started":true}', "application/json")

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[web] {self.address_string()} - {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MCP workflow dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            parser.error("The unauthenticated demo dashboard must bind to a loopback address")
    except ValueError:
        parser.error("--host must be a loopback IP address; DNS hostnames are not accepted")
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"MCP dashboard: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
