"""Punto de entrada declarativo del servidor MCP utilizando FastMCP."""

from mcp.server.fastmcp import FastMCP
from packet_tracer_mcp.tools.device_tools import execute_ping, send_cli_command
from packet_tracer_mcp.tools.topology_tools import (
    get_interface_status,
    get_routing_table,
    get_topology,
)

mcp = FastMCP(
    name="packet-tracer-mcp",
    instructions=(
        "Servidor MCP para telemetría, configuración CLI Cisco IOS y diagnóstico "
        "de topologías en Cisco Packet Tracer vía IPC TCP."
    ),
)

# Pilar 1: Topología y Telemetría
mcp.tool()(get_topology)
mcp.tool()(get_interface_status)
mcp.tool()(get_routing_table)

# Pilar 2: Configuración CLI
mcp.tool()(send_cli_command)

# Pilar 3: Diagnóstico
mcp.tool()(execute_ping)


def main() -> None:
    """Inicia la ejecución del servidor FastMCP."""
    mcp.run()


if __name__ == "__main__":
    main()

