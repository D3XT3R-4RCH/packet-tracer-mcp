"""Registro y exportación de herramientas (Tools) del servidor MCP."""

from packet_tracer_mcp.tools.device_tools import execute_ping, send_cli_command
from packet_tracer_mcp.tools.topology_tools import (
    get_interface_status,
    get_routing_table,
    get_topology,
)

__all__ = [
    "execute_ping",
    "get_interface_status",
    "get_routing_table",
    "get_topology",
    "send_cli_command",
]

