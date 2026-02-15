#!/bin/bash
# Start UwU Toolkit MCP Server in the Exegol container
# Usage: ./start.sh [--port PORT] [--debug]

CONTAINER="${EXEGOL_CONTAINER:-exegol-iron_throne}"
PORT="${1:-9400}"
UWU_ROOT="/opt/my-resources/tools/uwu-toolkit"

echo "[*] Starting UwU Toolkit MCP Server in ${CONTAINER}..."

# Check if already running
if docker exec "$CONTAINER" pgrep -f "uwu_mcp.run_server" >/dev/null 2>&1; then
    echo "[!] MCP server already running"
    docker exec "$CONTAINER" pgrep -af "uwu_mcp.run_server"
    exit 0
fi

# Start server
docker exec -d "$CONTAINER" bash -c "cd ${UWU_ROOT} && python3 -m uwu_mcp.run_server --host 0.0.0.0 --port ${PORT} >> /tmp/uwu_mcp.log 2>&1"

# Wait for startup
sleep 2

# Verify
if docker exec "$CONTAINER" pgrep -f "uwu_mcp.run_server" >/dev/null 2>&1; then
    CONTAINER_IP=$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
    echo "[+] MCP server running on http://${CONTAINER_IP}:${PORT}/uwu"
    echo "[+] Configure Claude Code MCP: http://${CONTAINER_IP}:${PORT}/uwu"
else
    echo "[-] Failed to start MCP server"
    docker exec "$CONTAINER" cat /tmp/uwu_mcp.log 2>&1 | tail -20
    exit 1
fi
