"""
Client that exercises every advanced feature of server.py.

  python client.py stdio
  python client.py http http://127.0.0.1:8000/mcp

Set ANTHROPIC_API_KEY (and `pip install anthropic`) for real sampling;
otherwise a stub answer is returned.
"""
import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypedDict

from opentelemetry import propagate, trace
from pydantic import FileUrl
from mcp import ClientSession, StdioServerParameters
from mcp.client.session import ListRootsFnT, LoggingFnT, SamplingFnT
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.context import RequestContext
from mcp.types import (
    CreateMessageRequestParams, CreateMessageResult, TextContent,
    ListRootsResult, Root, LoggingMessageNotificationParams,
    CallToolResult,
)

EventCallback = Callable[[dict[str, object]], None]
SamplingApproval = Callable[[str], Awaitable[str | None]]
ROOT_DIR = Path(os.environ.get("MCP_ROOT", Path(__file__).resolve().parent)).resolve()


class ClientCallbacks(TypedDict):
    sampling_callback: SamplingFnT
    list_roots_callback: ListRootsFnT
    logging_callback: LoggingFnT


# ---- Sampling: the server asks *us* to call an LLM -------------------------
def make_client_callbacks(
    emit: EventCallback | None = None,
    sampling_approval: SamplingApproval | None = None,
) -> ClientCallbacks:
    async def sampling_callback(
        context: RequestContext["ClientSession", Any],
        params: CreateMessageRequestParams,
    ) -> CreateMessageResult:
        with trace.get_tracer("mcp_advanced.client").start_as_current_span("mcp.client.sampling"):
            prompt_parts = []
            for message in params.messages:
                content = message.content
                if isinstance(content, TextContent):
                    prompt_parts.append(content.text)
                elif isinstance(content, list):
                    prompt_parts.extend(block.text for block in content if isinstance(block, TextContent))
            prompt = "\n".join(prompt_parts)
            if emit:
                emit({"type": "sampling", "title": "Server requested client sampling", "detail": prompt[:300]})
            if sampling_approval is not None:
                approved_prompt = await sampling_approval(prompt)
                if approved_prompt is None:
                    raise PermissionError("Sampling request was rejected or expired")
                prompt = approved_prompt
            if os.environ.get("ANTHROPIC_API_KEY"):
                import anthropic
                from anthropic.types import TextBlock

                client = anthropic.AsyncAnthropic()
                resp = await client.messages.create(
                    model=os.environ.get("MCP_MODEL", "claude-sonnet-4-6"),
                    max_tokens=params.maxTokens,
                    system=params.systemPrompt or "",
                    messages=[{"role": "user", "content": prompt}],
                )
                text = next((block.text for block in resp.content if isinstance(block, TextBlock)), "")
                model = resp.model
            else:
                text, model = f"[stub LLM] {prompt[:120]}...", "stub"
            if emit:
                emit({"type": "sampling", "title": f"Sampling response ({model})", "detail": text})
            return CreateMessageResult(role="assistant", model=model, content=TextContent(type="text", text=text))

    async def list_roots_callback(
        context: RequestContext["ClientSession", Any],
    ) -> ListRootsResult:
        if emit:
            emit({"type": "roots", "title": "Client granted a workspace root", "detail": str(ROOT_DIR)})
        return ListRootsResult(roots=[Root(uri=FileUrl(ROOT_DIR.as_uri()), name="workspace")])

    async def logging_callback(params: LoggingMessageNotificationParams) -> None:
        if emit:
            emit({"type": "log", "title": f"Server log · {params.level}", "detail": str(params.data)})
        else:
            print(f"  [log:{params.level}] {params.data}")

    return {
        "sampling_callback": sampling_callback,
        "list_roots_callback": list_roots_callback,
        "logging_callback": logging_callback,
    }


def _result_text(result: CallToolResult) -> str:
    return "\n".join(item.text for item in result.content if isinstance(item, TextContent))


async def run(session: ClientSession, emit: EventCallback | None = None) -> None:
    def event(kind: str, title: str, detail: str = "") -> None:
        if emit:
            emit({"type": kind, "title": title, "detail": detail})

    event("handshake", "Initializing MCP session")
    await session.initialize()  # required handshake: initialize -> initialized
    event("handshake", "MCP session initialized")

    tools = await session.list_tools()
    tool_names = [tool.name for tool in tools.tools]
    print("Tools:", tool_names)
    event("tools", "Discovered server tools", ", ".join(tool_names))

    event("tool", "Calling server_info")
    info = await session.call_tool("server_info", {})
    info_text = _result_text(info)
    print("\n== server_info"); print(info_text)
    event("result", "server_info result", info_text)
    try:
        transport_info = json.loads(info_text)
    except json.JSONDecodeError:
        transport_info = {}

    async def progress_callback(progress: float, total: float | None, message: str | None) -> None:
        pct = f"{progress / total:.0%}" if total else str(progress)
        detail = f"{pct} {message or ''}".strip()
        if emit:
            emit({"type": "progress", "title": "Long-running task", "detail": detail,
                  "progress": progress, "total": total})
        else:
            print(f"  [progress] {detail}")

    if not transport_info.get("stateless_http", False):
        event("tool", "Calling long_running_task", "4 steps · progress and logging notifications")
        print("\n== long_running_task")
        task_result = await session.call_tool(
            "long_running_task", {"steps": 4, "delay": 0.5}, progress_callback=progress_callback
        )
        task_text = _result_text(task_result)
        print(" ->", task_text)
        event("result", "long_running_task result", task_text)
    else:
        print("\n== long_running_task")
        print(" -> Skipped: stateless MCP does not keep a notification stream open")
        event("info", "Skipping notification demo", "Stateless MCP does not keep a notification stream open")

    event("tool", "Calling list_root_files", "Showing up to 3 Python files")
    print("\n== list_root_files")
    files_result = await session.call_tool("list_root_files", {"pattern": "*.py", "max_results": 3})
    files_text = _result_text(files_result)
    print(files_text)
    event("result", "Files visible in granted root", files_text or "No matching files")

    if not transport_info.get("stateless_http", False):
        event("tool", "Calling summarize_text", "The server will request sampling from the client")
        print("\n== summarize_text (sampling)")
        summary_result = await session.call_tool(
            "summarize_text",
            {"text": "MCP lets servers expose tools, resources and prompts to LLM apps. " * 5},
        )
        summary_text = _result_text(summary_result)
        print(" ->", summary_text)
        event("result", "summarize_text result", summary_text)
    else:
        print("\n== summarize_text (sampling)")
        print(" -> Skipped: sampling requires a stateful MCP client session")
        event("info", "Skipping sampling demo", "Sampling requires a stateful MCP client session")

    event("tool", "Testing root boundary", "Attempting to read a path outside the granted root")
    print("\n== path traversal must fail")
    boundary_result = await session.call_tool("read_root_file", {"path": "/etc/passwd"})
    boundary_text = "BLOCKED" if boundary_result.isError else _result_text(boundary_result)[:80]
    print(" ->", boundary_text)
    event("security", "Root boundary check", boundary_text)
    event("complete", "MCP workflow complete")


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    kw = make_client_callbacks()
    if mode == "stdio":
        params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).resolve().with_name("server.py"))]
        )
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w, **kw) as s:
                await run(s)
    else:
        url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000/mcp"
        access_token = os.environ.get("MCP_ACCESS_TOKEN")
        headers = {"Authorization": f"Bearer {access_token}"} if access_token else None
        with trace.get_tracer("mcp_advanced.client").start_as_current_span("mcp.client.session"):
            headers = headers or {}
            propagate.inject(headers)
            async with streamablehttp_client(url, headers=headers) as (r, w, get_session_id):
                async with ClientSession(r, w, **kw) as s:
                    await run(s)
                    print("\nSession id:", get_session_id())


if __name__ == "__main__":
    asyncio.run(main())
