"""Pruebas de integración End-to-End (E2E) entre PacketTracerClient y PacketTracerAgentServer."""

import asyncio
import pytest
from packet_tracer_mcp.bridge.client import (
    PacketTracerClient,
    PacketTracerProtocolError,
)
from packet_tracer_mcp.bridge.pt_agent import PacketTracerAgentServer
from packet_tracer_mcp.models.commands import (
    CliCommandRequest,
    CliCommandResponse,
    PingRequest,
    PingResponse,
)
from packet_tracer_mcp.models.devices import (
    HostnameRequest,
    InterfaceStatusResponse,
    RoutingTableResponse,
)
from packet_tracer_mcp.models.topology import DeviceType, TopologyResponse


@pytest.mark.asyncio
async def test_e2e_bridge_topology_and_cli_commands() -> None:
    """Verifica el flujo E2E completo (NDJSON sobre TCP) usando un puerto efímero (port=0)."""
    agent = PacketTracerAgentServer(host="127.0.0.1", port=0)
    server_task = asyncio.create_task(agent.start())

    try:
        await agent.wait_until_ready(timeout=5.0)
        ephemeral_port = agent.bound_port
        assert ephemeral_port > 0

        client = PacketTracerClient(
            host="127.0.0.1",
            port=ephemeral_port,
            timeout_seconds=5.0,
        )

        # 1. Prueba E2E de get_topology
        topology_raw = await client._send_request(
            action="get_topology",
            parameters={},
        )
        topology = TopologyResponse(**topology_raw)
        assert topology.total_devices == 3
        assert topology.total_links == 2
        assert topology.devices[0].hostname == "R1"
        assert topology.devices[0].device_type == DeviceType.ROUTER

        # 2. Prueba E2E de send_cli_command
        cli_req = CliCommandRequest(
            hostname="R1",
            commands=["configure terminal", "interface GigabitEthernet0/0", "no shutdown"],
            enable_mode=True,
        )
        cli_raw = await client._send_request(
            action="send_cli_command",
            parameters=cli_req.model_dump(mode="json"),
        )
        cli_resp = CliCommandResponse(**cli_raw)
        assert cli_resp.hostname == "R1"
        assert cli_resp.enable_mode is True
        assert len(cli_resp.results) == 3
        assert cli_resp.results[0].command == "configure terminal"
        assert cli_resp.results[0].success is True
        assert "R1#configure terminal" in cli_resp.results[0].output

        # 3. Prueba E2E de get_interface_status, get_routing_table y execute_ping
        host_req = HostnameRequest(hostname="R1")
        iface_raw = await client._send_request(
            action="get_interface_status",
            parameters=host_req.model_dump(mode="json"),
        )
        iface_resp = InterfaceStatusResponse(**iface_raw)
        assert iface_resp.hostname == "R1"
        assert len(iface_resp.interfaces) == 2

        routes_raw = await client._send_request(
            action="get_routing_table",
            parameters=host_req.model_dump(mode="json"),
        )
        routes_resp = RoutingTableResponse(**routes_raw)
        assert routes_resp.hostname == "R1"
        assert len(routes_resp.routes) == 4

        ping_req = PingRequest(
            source_hostname="PC1",
            destination_ip="192.168.10.1",
            count=4,
        )
        ping_raw = await client._send_request(
            action="execute_ping",
            parameters=ping_req.model_dump(mode="json"),
        )
        ping_resp = PingResponse(**ping_raw)
        assert ping_resp.source_hostname == "PC1"
        assert ping_resp.packets_sent == 4
        assert ping_resp.success_rate_percent == 100.0

        # 4. Prueba E2E de manejo de error ante acción inexistente
        with pytest.raises(PacketTracerProtocolError):
            await client._send_request(
                action="accion_inexistente",
                parameters={},
            )

    finally:
        await agent.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

