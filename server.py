"""Compatibility entry point for the packaged MCP server."""
from mcp_advanced.server import build_server, main

__all__ = ["build_server", "main"]

if __name__ == "__main__":
    main()
