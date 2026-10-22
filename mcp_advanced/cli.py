"""Administrative token issuer for locally trusted operators."""
from __future__ import annotations

import argparse

from .config import Settings
from .security import issue_token


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP platform administration")
    commands = parser.add_subparsers(dest="command", required=True)
    token_parser = commands.add_parser("issue-token", help="Issue a short-lived tenant capability token")
    token_parser.add_argument("--tenant", required=True)
    token_parser.add_argument("--user", required=True)
    token_parser.add_argument("--root", action="append", default=[], help="Tenant-relative workspace root")
    token_parser.add_argument(
        "--scope", action="append", default=["mcp:tools", "files:read", "sampling:request"],
        help="Capability scope; repeat to add scopes",
    )
    args = parser.parse_args()
    settings = Settings.from_env()
    print(issue_token(settings, args.tenant, args.user, args.scope, args.root))


if __name__ == "__main__":
    main()
