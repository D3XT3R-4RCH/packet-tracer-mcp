"""Exportación unificada de esquemas Pydantic v2 del servidor MCP."""

from packet_tracer_mcp.models.commands import (
    CliCommandOutputItem,
    CliCommandRequest,
    CliCommandResponse,
    PingRequest,
    PingResponse,
)
from packet_tracer_mcp.models.devices import (
    HostnameRequest,
    InterfaceStatusItem,
    InterfaceStatusResponse,
    OperationalStatus,
    RouteEntry,
    RouteProtocol,
    RoutingTableResponse,
)
from packet_tracer_mcp.models.ipc import (
    IPCRequestPayload,
    IPCResponsePayload,
    IPCStatus,
)
from packet_tracer_mcp.models.topology import (
    DeviceSummary,
    DeviceType,
    LinkStatus,
    PhysicalLink,
    TopologyResponse,
)

__all__ = [
    "CliCommandOutputItem",
    "CliCommandRequest",
    "CliCommandResponse",
    "DeviceSummary",
    "DeviceType",
    "HostnameRequest",
    "IPCRequestPayload",
    "IPCResponsePayload",
    "IPCStatus",
    "InterfaceStatusItem",
    "InterfaceStatusResponse",
    "LinkStatus",
    "OperationalStatus",
    "PhysicalLink",
    "PingRequest",
    "PingResponse",
    "RouteEntry",
    "RouteProtocol",
    "RoutingTableResponse",
    "TopologyResponse",
]
