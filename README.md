# Advanced MCP Platform

A Python 3.11+ FastMCP service that retains the original tool names while adding signed tenant capabilities, per-user workspace roots, bounded tool input, audit-friendly JSON logs, metrics, OpenTelemetry spans, and authenticated Streamable HTTP.

## Architecture

## MCP note: what it is and why use it

The **Model Context Protocol (MCP)** is an open standard for connecting AI applications (clients) to external capabilities and context (servers). A client can discover the server's available tools and call them through a consistent protocol, rather than using a different custom integration for every service. MCP also defines related capabilities such as resources, prompts, progress notifications, and client-controlled sampling.

In this project, the client initializes an MCP session, discovers tools such as `list_root_files` and `search_in_roots`, and sends structured tool requests. The server checks the caller's permissions, performs allowed work, then returns results and (where supported) progress/log notifications. For sampling, the server asks the client to generate text; the client remains responsible for whether and how it uses a model.

MCP is useful when you want reusable integrations with clear capability boundaries. It does not itself make a tool safe: the application still has to authenticate callers, validate inputs, enforce file access, and decide which capabilities to grant.

The dashboard's **MCP explained** section has a clickable process diagram; select a step to read its role in the request flow.

```text
MCP client
  ├─ stdio (local trusted process) ──────────────────────────────┐
  └─ Streamable HTTP + JWT → trace/auth middleware → FastMCP     │
                                                   ├─ tools ─────┤
                                                   ├─ sandbox    │
                                                   └─ sampling ←─┘
```

The control flow is: verify bearer token and required MCP scope; bind stateful MCP sessions to the tenant/user that initialized them; resolve signed workspace grants; enforce a per-principal tool rate limit; validate input; execute within a traced tool span; return a normal MCP result/error. The HTTP health/readiness routes are public; the MCP endpoint is not. No protocol extensions are introduced.

### Module layout

```text
mcp_advanced/
  config.py        Typed environment settings and startup validation
  security.py      JWT verifier, capability checks, rate limits, path sandbox
  observability.py JSON logging, audit events, metrics, OTel HTTP/tool spans
  server.py        FastMCP tools, auth configuration, health/metrics endpoints
  cli.py           Operator token issuer
server.py          Backward-compatible server entry point
client.py          Feature demo and authenticated HTTP client
webapp.py          Loopback-only interactive local demo dashboard
frontend/          Dashboard UI, event filtering, approval prompt, run history
tests/             Sandbox, auth, stdio, HTTP, and dashboard integration tests
```

## Local setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test,sampling]"
python -m pytest
```

The core sampling example uses a local stub; `.[sampling]` installs the optional Anthropic client for real sampling. Never put provider keys in the repository.

### stdio demo

```powershell
python client.py stdio
```

stdio is intended for a local trusted parent process. The root is `MCP_ROOT` when set, otherwise the project directory. Do not expose a stdio process with an untrusted caller as its parent.

### Authenticated, stateful HTTP

Set the same signing secret for the server and operator token issuer. Use a randomly generated value of at least 32 characters and keep it in a secret manager in deployed environments.

```powershell
$env:MCP_JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:MCP_DATA_DIR = "$PWD\.mcp-data"

# Create the server-side workspace root. Files for this user belong beneath it.
New-Item -ItemType Directory -Force "$env:MCP_DATA_DIR\tenants\acme\alice\roots\src" | Out-Null

# Issue a short-lived, least-privilege token. Copy its output for the client.
$token = python -m mcp_advanced.cli issue-token `
  --tenant acme --user alice --root src `
  --scope mcp:tools --scope files:read --scope sampling:request

# Terminal 1
python server.py --transport http

# Terminal 2
$env:MCP_JWT_SECRET = "<same signing secret>"
$env:MCP_DATA_DIR = "$PWD\.mcp-data"
$env:MCP_ACCESS_TOKEN = "<issued token>"
python client.py http http://127.0.0.1:8000/mcp
```

The token's `tenant_id`, `sub`, scopes, audience, issuer, expiry, and relative roots are validated. Tenant roots live beneath `MCP_DATA_DIR/tenants/<tenant>/<user>/roots`; relative grants cannot contain traversal. Supported scopes are `mcp:tools`, `files:read`, and `sampling:request`. The admin CLI is the trusted token issuer; do not expose it as an unauthenticated endpoint.

Useful settings:

| Variable | Default | Purpose |
|---|---|---|
| `MCP_JWT_SECRET` | unset | Required for HTTP; at least 32 characters |
| `MCP_JWT_ISSUER` | `https://auth.local.invalid` | Expected JWT issuer |
| `MCP_JWT_AUDIENCE` | `advanced-mcp` | Expected JWT audience |
| `MCP_JWT_TTL_SECONDS` | `900` | Short-lived token lifetime |
| `MCP_DATA_DIR` | `.mcp-data` | Tenant-isolated workspace storage |
| `MCP_ROOT` | project directory | Trusted local stdio root |
| `MCP_RATE_LIMIT_PER_MINUTE` | `60` | Per-user process-local tool rate |
| `MCP_SESSION_IDLE_TIMEOUT_SECONDS` | `1800` | Stateful session idle timeout |
| `MCP_MAX_SESSIONS` | `10000` | Maximum active stateful sessions |
| `MCP_MAX_FILE_BYTES` | `200000` | File read/search size bound |
| `MCP_MAX_SEARCH_FILES` | `500` | Search file-count bound |
| `MCP_STATELESS_HTTP` | `false` | Use stateless Streamable HTTP |
| `MCP_JSON_RESPONSE` | `false` | Disable SSE response streaming |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Enable OTLP trace export |

Configuration is parsed at startup and invalid security-sensitive values fail closed. HTTP startup without `MCP_JWT_SECRET` fails.

### Stateless HTTP

```powershell
$env:MCP_JWT_SECRET = "<random secret, at least 32 characters>"
$env:MCP_STATELESS_HTTP = "true"
python server.py --transport http
```

Stateless mode supports authenticated tools and signed per-user roots. As defined by Streamable HTTP/MCP behavior, it cannot preserve a client session for server-initiated sampling or a standing progress/log stream. The demo client skips those two exercises in stateless mode; `summarize_text` and `review_file` return a clear `sampling_unavailable` error if explicitly called. JSON-response mode likewise does not provide live notification delivery.

### Local browser dashboard

```powershell
python webapp.py
# Visit http://127.0.0.1:8080
```

The dashboard shows live tool/log/progress events, supports filtering, keeps recent run summaries in process memory, and pauses sampling for a human to approve/reject or edit the prompt. It binds only to a loopback IP because it has no authentication. It launches the local stdio demo, not the multi-tenant HTTP service; never expose it to a network or use it as a production tenant console.

### Docker Compose

```powershell
$env:MCP_JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up --build
```

The container runs as a non-root user, drops Linux capabilities, uses a read-only root filesystem, and keeps workspace data in a named volume. The compose port is loopback-bound by default. Configure an external OTLP collector by setting `OTEL_EXPORTER_OTLP_ENDPOINT`.

### Render deployment

This repository includes a Render Blueprint at `render.yaml` for the authenticated MCP HTTP service. It provisions a web service, generates `MCP_JWT_SECRET` in Render, stores tenant workspaces on a persistent disk, and checks `/ready`.

1. Push or merge this repository to GitHub.
2. In Render, choose **New → Blueprint**, connect `AHAAkash/Own_MCP_Server`, and select the branch containing `render.yaml`.
3. Review the Blueprint resources and confirm creation. Render may require a paid Starter service for the persistent disk.
4. Wait for the service to become healthy. Its MCP endpoint is `https://<your-render-service>.onrender.com/mcp`; `/health`, `/ready`, and `/metrics` are also available.
5. In Render's environment settings, copy the generated `MCP_JWT_SECRET` into a trusted local terminal (do not commit it), then issue a short-lived token:

```powershell
$env:MCP_JWT_SECRET = "<copy from Render environment settings>"
$env:MCP_JWT_ISSUER = "https://auth.local.invalid"
$env:MCP_JWT_AUDIENCE = "advanced-mcp"
$token = python -m mcp_advanced.cli issue-token `
  --tenant acme --user alice --root src `
  --scope mcp:tools --scope files:read --scope sampling:request
$env:MCP_ACCESS_TOKEN = $token
python client.py http https://<your-render-service>.onrender.com/mcp
```

Create or upload authorized workspace files beneath the persistent disk's `/var/data/tenants/<tenant>/<user>/roots/<root>` path using a trusted deployment workflow before requesting file tools. Do not make the disk publicly accessible.

Render deploys the MCP HTTP service only. The browser dashboard remains a loopback-only stdio demo and is intentionally not exposed by this Blueprint. Stateless mode is not enabled because the default demo uses MCP sampling and notifications. The service and disk incur Render charges according to your Render plan.

## Security and error model

- **Authentication:** HMAC-SHA256 JWTs with issuer, audience, expiry, user, tenant, scopes, and relative roots. There is no anonymous HTTP MCP access and no hard-coded development signing key.
- **Capabilities:** each tool checks its required scope. A file token does not automatically grant sampling.
- **Session isolation:** the stateful HTTP boundary binds the MCP session ID to the tenant/user that initialized it; session state itself is held in the FastMCP process.
- **Filesystem:** traversal, out-of-root absolute paths, and symlinks are rejected; hidden virtual environments and VCS trees are excluded from listing/search. Reads and searches have size, result, and file-count bounds and execute off the event loop.
- **Isolation:** HTTP workspace paths are separated by tenant and user; signed root grants are relative to that user's directory. The container uses a dedicated persistent volume. For mutually hostile tenants, use separate OS/container or volume boundaries as well; directory names alone are not a kernel security boundary.
- **Rate limits:** token-bucket limits are per user, but currently process-local.
- **Auditing:** authenticated tool calls, sampling requests/failures, and file read attempts emit structured JSON logs to stdout. Ship these logs to a protected centralized sink for durable retention.
- **Errors:** input, capability, path, sampling, and rate-limit failures include stable prefixes such as `invalid_input`, `insufficient_scope`, `path_forbidden`, `sampling_unavailable`, and `rate_limited`.
- **Observability:** tool and HTTP request spans, W3C trace-context extraction, sampling spans, tool latency, HTTP request counts, sampling success/failure, progress notification drops, and stateful HTTP session-duration metrics are available. Metrics are in process memory and exposed at `/metrics`; `/health` and `/ready` are unauthenticated liveness/readiness probes.

## Operational boundaries

This is a security-oriented single-process foundation and demo, not a finished multi-replica hosted service. Specifically:

- FastMCP's stateful session manager and the current rate limiter/metrics are in memory. Stateful HTTP must stay on one instance (or use deployment-level sticky routing); a Redis/Postgres session-store adapter and distributed rate limiter are not implemented.
- Workspace directories share the configured volume at the OS level; hostile-tenant deployments need stronger container/volume isolation.
- JSON audit output is not a durable audit database. Configure log collection, retention, redaction, alerting, and key rotation before production use.
- Sampling has timeouts and explicit errors but no circuit breaker. The dashboard approval queue/run history are process-local and intentionally loopback-only.
- MCP resources for files/prior results and persistent project/run-history APIs are not implemented.
- OTLP traces export only when the endpoint is configured. Protect trace/log backends and avoid recording sensitive prompt/file contents there.

Do not treat a successful build or a local demo as evidence of compliance or production approval. Before internet-facing deployment, add an organizational identity/token issuer, secret rotation and revocation, shared distributed state/rate-limit storage, durable audit retention, per-tenant runtime isolation, resource quotas, and load/security testing.

## Tests

```powershell
python -m pytest
mypy mcp_advanced client.py webapp.py server.py tests
```

The suite covers token validation, capabilities, traversal/symlink rejection, tenant root separation, rate limiting, stdio operation from a different working directory, authenticated and unauthenticated stateful HTTP, stateless HTTP file tools, and dashboard sampling approval/history.
