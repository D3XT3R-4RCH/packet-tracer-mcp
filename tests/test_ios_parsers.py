"""Suite de pruebas unitarias exhaustivas para los parsers CLI de Cisco IOS (`ios_parsers.py`)."""

import asyncio
import pytest
from packet_tracer_mcp.bridge.ios_parsers import (
    parse_interface_status,
    parse_ping_output,
    parse_show_ip_route,
    sanitize_console_output,
)
from packet_tracer_mcp.bridge.pt_api import NativePacketTracerAPI, classify_device_type
from packet_tracer_mcp.models.commands import CliCommandResponse, PingResponse
from packet_tracer_mcp.models.devices import (
    InterfaceStatusResponse,
    OperationalStatus,
    RouteProtocol,
    RoutingTableResponse,
)
from packet_tracer_mcp.models.topology import DeviceType, TopologyResponse


class TestSanitizeConsoleOutput:
    """Verifica la limpieza de artefactos de consola de Packet Tracer."""

    def test_removes_more_pagination_backspaces_and_cr(self) -> None:
        raw = "R1#show ip route\r\nCodes: C - connected\r\n --More-- \x08\x08\x08\x08\x08\x08\x08\x08\x08C 10.0.0.0/8 is directly connected, Gi0/0\r"
        cleaned = sanitize_console_output(raw)
        assert "--More--" not in cleaned
        assert "\x08" not in cleaned
        assert "\r" not in cleaned
        assert "C 10.0.0.0/8 is directly connected, Gi0/0" in cleaned


class TestParseShowIpRoute:
    """Verifica la extracción de tablas de enrutamiento complejas y casos extremos."""

    def test_complex_ospf_inherited_subnets_and_gateway_of_last_resort(self) -> None:
        raw_table = (
            "R1#show ip route\r\n"
            "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\r\n"
            "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\r\n"
            "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2\r\n"
            "       E1 - OSPF external type 1, E2 - OSPF external type 2\r\n"
            "\r\n"
            "Gateway of last resort is 192.168.10.254 to network 0.0.0.0\r\n"
            "\r\n"
            "     10.0.0.0/24 is subnetted, 2 subnets\r\n"
            "O       10.1.1.0 [110/2] via 192.168.10.2, 00:14:22, GigabitEthernet0/0\r\n"
            "O IA    10.1.2.0 [110/66] via 192.168.10.3, 00:05:10, Serial0/0/0\r\n"
            "--More--\x08\x08\x08\x08\x08\x08\x08\x08"
            "     172.16.0.0/16 is variably subnetted, 2 subnets, 2 masks\r\n"
            "D EX    172.16.50.0/24 [170/256000] via 192.168.10.4, 00:01:00, GigabitEthernet0/0\r\n"
            "     192.168.10.0/24 is variably subnetted, 2 subnets, 2 masks\r\n"
            "C       192.168.10.0/24 is directly connected, GigabitEthernet0/0\r\n"
            "L       192.168.10.1/32 is directly connected, GigabitEthernet0/0\r\n"
            "O E2 198.51.100.0/24 [110/20] via 192.168.10.2, 00:10:00, GigabitEthernet0/0\r\n"
            "S*   0.0.0.0/0 [1/0] via 192.168.10.254\r\n"
        )

        routes = parse_show_ip_route(raw_table)
        assert len(routes) == 7

        # Validar compatibilidad directa con el modelo Pydantic RoutingTableResponse
        model = RoutingTableResponse(hostname="R1", routes=routes)
        assert model.hostname == "R1"
        assert len(model.routes) == 7

        # 1. Ruta OSPF con prefijo heredado (/24 del encabezado 10.0.0.0/24)
        assert model.routes[0].protocol == RouteProtocol.OSPF
        assert str(model.routes[0].network) == "10.1.1.0"
        assert model.routes[0].prefix_length == 24
        assert str(model.routes[0].next_hop) == "192.168.10.2"
        assert model.routes[0].administrative_distance == 110
        assert model.routes[0].metric == 2
        assert model.routes[0].outgoing_interface == "GigabitEthernet0/0"

        # 2. Ruta OSPF Inter-Area (O IA) con prefijo heredado (/24)
        assert model.routes[1].protocol == RouteProtocol.OSPF_IA
        assert str(model.routes[1].network) == "10.1.2.0"
        assert model.routes[1].prefix_length == 24
        assert model.routes[1].outgoing_interface == "Serial0/0/0"

        # 3. Ruta EIGRP External (D EX)
        assert model.routes[2].protocol == RouteProtocol.EIGRP_EX
        assert model.routes[2].administrative_distance == 170

        # 4. Ruta Conectada (C) y Local (L)
        assert model.routes[3].protocol == RouteProtocol.CONNECTED
        assert model.routes[3].next_hop is None
        assert model.routes[4].protocol == RouteProtocol.LOCAL
        assert model.routes[4].prefix_length == 32

        # 5. Ruta OSPF External Type 2 (O E2)
        assert model.routes[5].protocol == RouteProtocol.OSPF_E2

        # 6. Ruta Estática por defecto (S* -> S) sin interfaz de salida explícita
        assert model.routes[6].protocol == RouteProtocol.STATIC
        assert str(model.routes[6].network) == "0.0.0.0"
        assert model.routes[6].prefix_length == 0
        assert str(model.routes[6].next_hop) == "192.168.10.254"
        assert model.routes[6].outgoing_interface is None


class TestParsePingOutput:
    """Verifica el parser de estadísticas ICMP en escenarios de éxito, pérdida total y PC-PT."""

    def test_ios_ping_full_success(self) -> None:
        raw = (
            "Type escape sequence to abort.\r\n"
            "Sending 5, 100-byte ICMP Echos to 192.168.10.1, timeout is 2 seconds:\r\n"
            "!!!!!\r\n"
            "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/3/8 ms\r\n"
        )
        parsed = parse_ping_output(raw)
        resp = PingResponse(
            source_hostname="R1",
            destination_ip="192.168.10.1",
            **parsed,
        )
        assert resp.packets_sent == 5
        assert resp.packets_received == 5
        assert resp.success_rate_percent == 100.0
        assert resp.rtt_min_ms == 1.0
        assert resp.rtt_avg_ms == 3.0
        assert resp.rtt_max_ms == 8.0

    def test_ios_ping_zero_percent_timeout(self) -> None:
        """Caso extremo: 0% de éxito donde Cisco IOS omite la sección round-trip min/avg/max."""
        raw = (
            "Type escape sequence to abort.\r\n"
            "Sending 5, 100-byte ICMP Echos to 10.99.99.99, timeout is 2 seconds:\r\n"
            ".....\r\n"
            "Success rate is 0 percent (0/5)\r\n"
        )
        parsed = parse_ping_output(raw)
        resp = PingResponse(
            source_hostname="R1",
            destination_ip="10.99.99.99",
            **parsed,
        )
        assert resp.packets_sent == 5
        assert resp.packets_received == 0
        assert resp.success_rate_percent == 0.0
        assert resp.rtt_min_ms is None
        assert resp.rtt_avg_ms is None
        assert resp.rtt_max_ms is None

    def test_pc_pt_command_prompt_ping_format(self) -> None:
        """Soporte para el formato de salida del Command Prompt en terminales PC-PT."""
        raw = (
            "Pinging 192.168.10.1 with 32 bytes of data:\r\n\r\n"
            "Reply from 192.168.10.1: bytes=32 time=2ms TTL=128\r\n"
            "Reply from 192.168.10.1: bytes=32 time=4ms TTL=128\r\n\r\n"
            "Ping statistics for 192.168.10.1:\r\n"
            "    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),\r\n"
            "Approximate round trip times in milli-seconds:\r\n"
            "    Minimum = 1ms, Maximum = 4ms, Average = 2ms\r\n"
        )
        parsed = parse_ping_output(raw)
        assert parsed["packets_sent"] == 4
        assert parsed["packets_received"] == 3
        assert parsed["success_rate_percent"] == 75.0
        assert parsed["rtt_min_ms"] == 1.0
        assert parsed["rtt_avg_ms"] == 2.0
        assert parsed["rtt_max_ms"] == 4.0

    def test_invalid_ping_output_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            parse_ping_output("% Invalid input detected at '^' marker.")


class TestParseInterfaceStatus:
    """Verifica la extracción de interfaces desde `show ip interface brief` y `show interfaces`."""

    def test_combined_brief_and_detail_output(self) -> None:
        brief = (
            "R1#show ip interface brief\r\n"
            "Interface              IP-Address      OK? Method Status                Protocol\r\n"
            "GigabitEthernet0/0     192.168.10.1    YES manual up                    up\r\n"
            "GigabitEthernet0/1     unassigned      YES unset  administratively down down\r\n"
            "Vlan1                  unassigned      YES unset  down                  down\r\n"
        )
        detail = (
            "GigabitEthernet0/0 is up, line protocol is up (connected)\r\n"
            "  Hardware is CN Gigabit Ethernet, address is 0001.42a1.0b01 (bia 0001.42a1.0b01)\r\n"
            "  Internet address is 192.168.10.1/24\r\n"
            "  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec,\r\n"
            "GigabitEthernet0/1 is administratively down, line protocol is down (disabled)\r\n"
            "  Hardware is CN Gigabit Ethernet, address is 0001.42a1.0b02 (bia 0001.42a1.0b02)\r\n"
        )

        items = parse_interface_status(brief_output=brief, detail_output=detail)
        assert len(items) == 3

        resp = InterfaceStatusResponse(hostname="R1", interfaces=items)
        assert resp.hostname == "R1"

        gi0 = resp.interfaces[0]
        assert gi0.interface_name == "GigabitEthernet0/0"
        assert gi0.physical_status == OperationalStatus.UP
        assert gi0.protocol_status == OperationalStatus.UP
        assert str(gi0.ip_address) == "192.168.10.1"
        assert str(gi0.subnet_mask) == "255.255.255.0"
        assert gi0.mac_address == "0001.42A1.0B01"

        gi1 = resp.interfaces[1]
        assert gi1.interface_name == "GigabitEthernet0/1"
        assert gi1.physical_status == OperationalStatus.ADMIN_DOWN
        assert gi1.protocol_status == OperationalStatus.DOWN
        assert gi1.ip_address is None
        assert gi1.subnet_mask is None
        assert gi1.mac_address == "0001.42A1.0B02"

        vlan1 = resp.interfaces[2]
        assert vlan1.interface_name == "Vlan1"
        assert vlan1.physical_status == OperationalStatus.DOWN
        assert vlan1.mac_address is None


class TestNativePacketTracerAPIParsersIntegration:
    """Verifica que NativePacketTracerAPI integre correctamente los parsers CLI."""

    @pytest.mark.asyncio
    async def test_native_api_methods_with_injected_cli_transport(self) -> None:
        async def fake_cli_transport(hostname: str, command: str, enable_mode: bool) -> str:
            if command == "show ip interface brief":
                return (
                    "Interface              IP-Address      OK? Method Status                Protocol\r\n"
                    "GigabitEthernet0/0     192.168.10.1    YES manual up                    up\r\n"
                )
            if command == "show interfaces":
                return (
                    "GigabitEthernet0/0 is up, line protocol is up (connected)\r\n"
                    "  Hardware is CN Gigabit Ethernet, address is 0001.42a1.0b01 (bia 0001.42a1.0b01)\r\n"
                    "  Internet address is 192.168.10.1/24\r\n"
                )
            if command == "show ip route":
                return "C    192.168.10.0/24 is directly connected, GigabitEthernet0/0\r\n"
            if command.startswith("ping "):
                return (
                    "Sending 5, 100-byte ICMP Echos to 192.168.10.2, timeout is 2 seconds:\r\n"
                    "!!!!!\r\n"
                    "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/3 ms\r\n"
                )
            if command == "invalid_cmd":
                return "% Invalid input detected at '^' marker.\r\n"
            return f"{hostname}# {command}\r\n"

        native_api = NativePacketTracerAPI(cli_transport=fake_cli_transport)

        # 1. get_interface_status
        iface_dict = await native_api.get_interface_status("R1")
        iface_model = InterfaceStatusResponse(**iface_dict)
        assert len(iface_model.interfaces) == 1
        assert iface_model.interfaces[0].mac_address == "0001.42A1.0B01"
        assert str(iface_model.interfaces[0].subnet_mask) == "255.255.255.0"

        # 2. get_routing_table
        route_dict = await native_api.get_routing_table("R1")
        route_model = RoutingTableResponse(**route_dict)
        assert len(route_model.routes) == 1
        assert route_model.routes[0].protocol == RouteProtocol.CONNECTED

        # 3. execute_ping
        ping_dict = await native_api.execute_ping("R1", "192.168.10.2", count=5)
        ping_model = PingResponse(**ping_dict)
        assert ping_model.success_rate_percent == 100.0
        assert ping_model.rtt_avg_ms == 2.0

        # 4. send_cli_command (detección de éxito y error '% Invalid input')
        cli_dict = await native_api.send_cli_command(
            hostname="R1",
            commands=["configure terminal", "invalid_cmd"],
            enable_mode=True,
        )
        cli_model = CliCommandResponse(**cli_dict)
        assert cli_model.results[0].success is True
        assert cli_model.results[1].success is False

    @pytest.mark.asyncio
    async def test_native_get_topology_hierarchical_traversal_and_deduplication(self) -> None:
        """Verifica que get_topology recorra nodos/puertos/enlaces y deduplique cables bidireccionales."""

        class FakeNamedObj:
            def __init__(self, name: str) -> None:
                self._name = name

            def getName(self) -> str:
                return self._name

        class FakeLink:
            def __init__(self, d1: str, p1: str, d2: str, p2: str) -> None:
                self._d1 = FakeNamedObj(d1)
                self._p1 = FakeNamedObj(p1)
                self._d2 = FakeNamedObj(d2)
                self._p2 = FakeNamedObj(p2)

            def getDevice1(self) -> FakeNamedObj:
                return self._d1

            def getPort1(self) -> FakeNamedObj:
                return self._p1

            def getDevice2(self) -> FakeNamedObj:
                return self._d2

            def getPort2(self) -> FakeNamedObj:
                return self._p2

            def getCableType(self) -> str:
                return "copper_straight"

            def getStatus(self) -> str:
                return "up"

        shared_link = FakeLink("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1")

        class FakePort:
            def __init__(self, name: str, link: FakeLink | None) -> None:
                self._name = name
                self._link = link

            def getName(self) -> str:
                return self._name

            def getLink(self) -> FakeLink | None:
                return self._link

        class FakeDevice:
            def __init__(self, name: str, model: str, ports: list[FakePort]) -> None:
                self._name = name
                self._model = model
                self._ports = ports

            def getName(self) -> str:
                return self._name

            def getModel(self) -> str:
                return self._model

            def getPower(self) -> bool:
                return True

            def getPortCount(self) -> int:
                return len(self._ports)

            def getPortAt(self, idx: int) -> FakePort:
                return self._ports[idx]

        class FakeNetwork:
            def __init__(self) -> None:
                self._devices = [
                    FakeDevice("R1", "2911", [FakePort("GigabitEthernet0/0", shared_link)]),
                    FakeDevice("SW1", "2960-24TT", [FakePort("GigabitEthernet0/1", shared_link)]),
                    FakeDevice("PC1", "PC-PT", [FakePort("FastEthernet0", None)]),
                ]

            def getDeviceCount(self) -> int:
                return len(self._devices)

            def getDeviceAt(self, idx: int) -> FakeDevice:
                return self._devices[idx]

        assert classify_device_type("2911") == DeviceType.ROUTER
        assert classify_device_type("2960-24TT") == DeviceType.SWITCH
        assert classify_device_type("3560-24PS") == DeviceType.MULTILAYER_SWITCH
        assert classify_device_type("PC-PT") == DeviceType.PC
        assert classify_device_type("ASA5505") == DeviceType.FIREWALL

        native_api = NativePacketTracerAPI(ipc_network_provider=FakeNetwork)
        topo_dict = await native_api.get_topology()
        topo_model = TopologyResponse(**topo_dict)

        assert topo_model.total_devices == 3
        assert topo_model.total_links == 1
        assert topo_model.devices[0].device_type == DeviceType.ROUTER
        assert topo_model.devices[1].device_type == DeviceType.SWITCH
        assert topo_model.devices[2].device_type == DeviceType.PC
        assert topo_model.links[0].source_hostname == "R1"
        assert topo_model.links[0].target_hostname == "SW1"

    @pytest.mark.asyncio
    async def test_native_connect_and_disconnect_socket(self) -> None:
        """Verifica la apertura y cierre limpio del socket TCP en connect() y disconnect()."""

        async def dummy_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(dummy_handler, host="127.0.0.1", port=0)
        ephemeral_port = int(server.sockets[0].getsockname()[1])

        try:
            native_api = NativePacketTracerAPI(
                pt_ipc_host="127.0.0.1",
                pt_ipc_port=ephemeral_port,
            )
            assert native_api.is_connected is False
            await native_api.connect(perform_handshake=False)
            assert native_api.is_connected is True
            await native_api.disconnect()
            assert native_api.is_connected is False
        finally:
            server.close()
            await server.wait_closed()

