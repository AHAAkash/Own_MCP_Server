from __future__ import annotations

import os
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from mcp_advanced.config import Settings
from mcp_advanced.security import issue_token

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_stdio_transport_from_external_working_directory(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["MCP_ROOT"] = str(PROJECT_ROOT)
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "client.py"), "stdio"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BLOCKED" in result.stdout
    assert "summarize_text" in result.stdout


def test_authenticated_stateful_http_transport(tmp_path: Path) -> None:
    secret = "test-secret-key-that-is-at-least-thirty-two-bytes"
    port = _free_port()
    env = os.environ.copy()
    env.update({
        "MCP_JWT_SECRET": secret,
        "MCP_DATA_DIR": str(tmp_path / "data"),
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(port),
        "MCP_STATELESS_HTTP": "false",
    })
    token = issue_token(
        Settings(jwt_secret=secret, data_dir=tmp_path / "data"),
        "test-tenant",
        "test-user",
        ["mcp:tools", "files:read", "sampling:request"],
        ["src"],
    )
    server = subprocess.Popen(
        [sys.executable, str(PROJECT_ROOT / "server.py"), "--transport", "http"],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise AssertionError(f"HTTP server exited early with code {server.returncode}")
            try:
                with urllib.request.urlopen(base + "/health", timeout=1) as response:
                    assert response.status == 200
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        else:
            raise AssertionError("HTTP server did not become healthy")
        with urllib.request.urlopen(base + "/ready", timeout=3) as response:
            assert response.status == 200

        request = urllib.request.Request(
            base + "/mcp",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("Unauthenticated MCP request was accepted")

        client_env = env.copy()
        client_env["MCP_ACCESS_TOKEN"] = token
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "client.py"), "http", base + "/mcp"],
            cwd=PROJECT_ROOT,
            env=client_env,
            capture_output=True,
            text=True,
            timeout=40,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "BLOCKED" in result.stdout
        assert "client_supports_sampling" in result.stdout
        with urllib.request.urlopen(base + "/metrics", timeout=3) as response:
            assert "mcp_tool_duration_seconds_count" in response.read().decode()
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def test_stateless_http_keeps_token_scoped_file_tools(tmp_path: Path) -> None:
    secret = "test-secret-key-that-is-at-least-thirty-two-bytes"
    port = _free_port()
    data_dir = tmp_path / "data"
    env = os.environ.copy()
    env.update({
        "MCP_JWT_SECRET": secret,
        "MCP_DATA_DIR": str(data_dir),
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(port),
        "MCP_STATELESS_HTTP": "true",
    })
    token = issue_token(
        Settings(jwt_secret=secret, data_dir=data_dir),
        "test-tenant",
        "test-user",
        ["mcp:tools", "files:read", "sampling:request"],
        ["src"],
    )
    server = subprocess.Popen(
        [sys.executable, str(PROJECT_ROOT / "server.py"), "--transport", "http"],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise AssertionError(f"HTTP server exited early with code {server.returncode}")
            try:
                urllib.request.urlopen(base + "/health", timeout=1).close()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        else:
            raise AssertionError("Stateless server did not become healthy")
        client_env = env.copy()
        client_env["MCP_ACCESS_TOKEN"] = token
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "client.py"), "http", base + "/mcp"],
            cwd=PROJECT_ROOT,
            env=client_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert '"stateless_http": true' in result.stdout
        assert "Skipped: sampling requires a stateful MCP client session" in result.stdout
        assert "BLOCKED" in result.stdout
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def test_dashboard_human_sampling_approval_and_run_history(tmp_path: Path) -> None:
    port = _free_port()
    server = subprocess.Popen(
        [sys.executable, str(PROJECT_ROOT / "webapp.py"), "--port", str(port)],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise AssertionError(f"Dashboard exited early with code {server.returncode}")
            try:
                urllib.request.urlopen(base, timeout=1).close()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        else:
            raise AssertionError("Dashboard did not start")

        bad_host = urllib.request.Request(base + "/", headers={"Host": "attacker.example"})
        try:
            urllib.request.urlopen(bad_host, timeout=3)
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("Dashboard accepted an untrusted Host header")

        bad_origin = urllib.request.Request(
            base + "/api/run",
            data=b"",
            headers={"Origin": "http://attacker.example"},
            method="POST",
        )
        try:
            urllib.request.urlopen(bad_origin, timeout=3)
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("Dashboard accepted an untrusted Origin header")

        request = urllib.request.Request(base + "/api/run", data=b"", method="POST")
        with urllib.request.urlopen(request, timeout=3) as response:
            assert response.status == 200
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with urllib.request.urlopen(base + "/api/state", timeout=2) as response:
                state = json.load(response)
            approval = next((event for event in state["events"] if event["type"] == "approval_required"), None)
            if approval:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Sampling approval was not requested")

        payload = json.dumps({
            "approved": True,
            "prompt": "Approved edited prompt for the local demo",
        }).encode()
        approval_request = urllib.request.Request(
            base + "/api/sampling/" + approval["approval_id"],
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(approval_request, timeout=3) as response:
            assert response.status == 200
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with urllib.request.urlopen(base + "/api/state", timeout=2) as response:
                state = json.load(response)
            if not state["running"] and state["runs"]:
                break
            time.sleep(0.2)
        assert state["runs"][0]["status"] == "complete"
        assert any("Approved edited prompt" in event["detail"] for event in state["events"])
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
