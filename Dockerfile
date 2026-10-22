FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml requirements.txt ./
COPY mcp_advanced ./mcp_advanced
RUN python -m pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_DATA_DIR=/var/lib/mcp/data
RUN groupadd --system mcp && useradd --system --gid mcp --home-dir /var/lib/mcp mcp \
    && mkdir -p /var/lib/mcp/data \
    && chown -R mcp:mcp /var/lib/mcp
COPY --from=build /install /usr/local
WORKDIR /app
COPY server.py ./
COPY mcp_advanced ./mcp_advanced
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["python", "-m", "mcp_advanced.server", "--transport", "http"]
