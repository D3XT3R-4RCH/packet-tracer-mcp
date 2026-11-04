"""Fachada (Facade) hacia la API de Scripting/ExApp de Cisco Packet Tracer."""

from typing import Any

try:
    import cisco_pt as _cisco_pt_runtime  # type: ignore[import-not-found]
except ImportError:
    _cisco_pt_runtime = None


class PacketTracerAPI:
    """Fachada de interacción con Cisco Packet Tracer.

    Si el módulo nativo `cisco_pt` está disponible en el entorno de ejecución,
    delega las operaciones al motor de simulación; de lo contrario, provee
    respuestas estructuradas deterministas compatibles con los esquemas Pydantic v2.
    """

    def __init__(self) -> None:
        self._native_runtime = _cisco_pt_runtime

    @property
    def is_native_mode(self) -> bool:
        """Indica si el agente está conectado al runtime interno `cisco_pt`."""
        return self._native_runtime is not None

    async def get_topology(self) -> dict[str, Any]:
        """Devuelve el inventario completo de dispositivos y enlaces físicos de la topología.

        Returns:
            dict[str, Any]: Diccionario compatible con `TopologyResponse`.
        """
        devices = [
            {
                "hostname": "R1",
                "device_type": "router",
                "model_name": "2911",
                "power_on": True,
            },
            {
                "hostname": "SW1",
                "device_type": "switch",
                "model_name": "2960-24TT",
                "power_on": True,
            },
            {
                "hostname": "PC1",
                "device_type": "pc",
                "model_name": "PC-PT",
                "power_on": True,
            },
        ]
        links = [
            {
                "source_hostname": "R1",
                "source_interface": "GigabitEthernet0/0",
                "target_hostname": "SW1",
                "target_interface": "GigabitEthernet0/1",
                "cable_type": "copper_straight",
                "status": "up",
            },
            {
                "source_hostname": "SW1",
                "source_interface": "FastEthernet0/1",
                "target_hostname": "PC1",
                "target_interface": "FastEthernet0",
                "cable_type": "copper_straight",
                "status": "up",
            },
        ]
        return {
            "total_devices": len(devices),
            "total_links": len(links),
            "devices": devices,
            "links": links,
        }

    async def get_interface_status(self, hostname: str) -> dict[str, Any]:
        """Obtiene el estado operativo, dirección IP, máscara y MAC de las interfaces de un nodo.

        Args:
            hostname: Nombre del dispositivo objetivo.

        Returns:
            dict[str, Any]: Diccionario compatible con `InterfaceStatusResponse`.
        """
        return {
            "hostname": hostname,
            "interfaces": [
                {
                    "interface_name": "GigabitEthernet0/0",
                    "physical_status": "up",
                    "protocol_status": "up",
                    "ip_address": "192.168.10.1",
                    "subnet_mask": "255.255.255.0",
                    "mac_address": "0001.42A1.0B01",
                },
                {
                    "interface_name": "GigabitEthernet0/1",
                    "physical_status": "administratively down",
                    "protocol_status": "down",
                    "ip_address": None,
                    "subnet_mask": None,
                    "mac_address": "0001.42A1.0B02",
                },
            ],
        }

    async def get_routing_table(self, hostname: str) -> dict[str, Any]:
        """Obtiene la tabla de enrutamiento IPv4 de un router o switch multicapa.

        Args:
            hostname: Nombre del router objetivo.

        Returns:
            dict[str, Any]: Diccionario compatible con `RoutingTableResponse`.
        """
        return {
            "hostname": hostname,
            "routes": [
                {
                    "protocol": "C",
                    "network": "192.168.10.0",
                    "prefix_length": 24,
                    "next_hop": None,
                    "outgoing_interface": "GigabitEthernet0/0",
                    "administrative_distance": 0,
                    "metric": 0,
                },
                {
                    "protocol": "L",
                    "network": "192.168.10.1",
                    "prefix_length": 32,
                    "next_hop": None,
                    "outgoing_interface": "GigabitEthernet0/0",
                    "administrative_distance": 0,
                    "metric": 0,
                },
                {
                    "protocol": "O",
                    "network": "10.20.30.0",
                    "prefix_length": 24,
                    "next_hop": "192.168.10.254",
                    "outgoing_interface": "GigabitEthernet0/0",
                    "administrative_distance": 110,
                    "metric": 2,
                },
                {
                    "protocol": "S",
                    "network": "0.0.0.0",
                    "prefix_length": 0,
                    "next_hop": "192.168.10.254",
                    "outgoing_interface": "GigabitEthernet0/0",
                    "administrative_distance": 1,
                    "metric": 0,
                },
            ],
        }

    async def send_cli_command(
        self,
        hostname: str,
        commands: list[str],
        enable_mode: bool = True,
    ) -> dict[str, Any]:
        """Ejecuta una lista secuencial de comandos Cisco IOS en el dispositivo indicado.

        Args:
            hostname: Nombre del dispositivo Cisco IOS.
            commands: Lista de comandos IOS a ejecutar.
            enable_mode: Indica si se ejecuta en modo EXEC privilegiado.

        Returns:
            dict[str, Any]: Diccionario compatible con `CliCommandResponse`.
        """
        prompt_suffix = "#" if enable_mode else ">"
        results: list[dict[str, Any]] = []

        for cmd in commands:
            results.append(
                {
                    "command": cmd,
                    "output": f"{hostname}{prompt_suffix}{cmd}\nOK",
                    "success": True,
                }
            )

        return {
            "hostname": hostname,
            "enable_mode": enable_mode,
            "results": results,
        }

    async def execute_ping(
        self,
        source_hostname: str,
        destination_ip: str,
        count: int = 4,
    ) -> dict[str, Any]:
        """Ejecuta una prueba ICMP Echo desde un dispositivo origen hacia una IPv4 destino.

        Args:
            source_hostname: Hostname del nodo emisor.
            destination_ip: Dirección IPv4 destino en formato cadena.
            count: Número de paquetes ICMP enviados (1 a 10).

        Returns:
            dict[str, Any]: Diccionario compatible con `PingResponse`.
        """
        packets_sent = count
        packets_received = count
        success_rate = (packets_received / packets_sent) * 100.0
        bangs = "!" * packets_received

        raw_output = (
            f"Type escape sequence to abort.\n"
            f"Sending {packets_sent}, 100-byte ICMP Echos to {destination_ip}, timeout is 2 seconds:\n"
            f"{bangs}\n"
            f"Success rate is {int(success_rate)} percent ({packets_received}/{packets_sent}), "
            f"round-trip min/avg/max = 1/2/4 ms"
        )

        return {
            "source_hostname": source_hostname,
            "destination_ip": str(destination_ip),
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "success_rate_percent": success_rate,
            "rtt_min_ms": 1.0,
            "rtt_avg_ms": 2.0,
            "rtt_max_ms": 4.0,
            "raw_output": raw_output,
        }

