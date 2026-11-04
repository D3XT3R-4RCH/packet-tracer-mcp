"""Fachada (Facade) hacia la API de Scripting/ExApp de Cisco Packet Tracer."""

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import Any
from packet_tracer_mcp.bridge.ios_parsers import (
    parse_interface_status,
    parse_ping_output,
    parse_show_ip_route,
    sanitize_console_output,
)
from packet_tracer_mcp.config import settings
from packet_tracer_mcp.models.topology import DeviceType, LinkStatus

try:
    import cisco_pt as _cisco_pt_runtime  # type: ignore[import-not-found]
except ImportError:
    _cisco_pt_runtime = None

# Patrón pre-compilado para detectar errores sintácticos o de ejecución en consola Cisco IOS
_IOS_CLI_ERROR_RE = re.compile(
    r"^%\s*(?:Invalid\s+input|Incomplete\s+command|Ambiguous\s+command|Unknown\s+command|"
    r"Bad\s+IP\s+address|Error\s+opening|Unrecognized\s+host)",
    re.IGNORECASE | re.MULTILINE,
)

# Mapa estático interno de modelos comunes de Packet Tracer hacia DeviceType
_STATIC_DEVICE_MODEL_MAP: dict[str, DeviceType] = {
    # Routers Cisco IOS
    "1841": DeviceType.ROUTER,
    "1941": DeviceType.ROUTER,
    "2620xm": DeviceType.ROUTER,
    "2621xm": DeviceType.ROUTER,
    "2811": DeviceType.ROUTER,
    "2901": DeviceType.ROUTER,
    "2911": DeviceType.ROUTER,
    "4321": DeviceType.ROUTER,
    "4331": DeviceType.ROUTER,
    "isr4321": DeviceType.ROUTER,
    "isr4331": DeviceType.ROUTER,
    "router-pt": DeviceType.ROUTER,
    "router-pt-empty": DeviceType.ROUTER,
    "819": DeviceType.ROUTER,
    "829": DeviceType.ROUTER,
    # Switches Multicapa (Layer 3)
    "3560-24ps": DeviceType.MULTILAYER_SWITCH,
    "3560": DeviceType.MULTILAYER_SWITCH,
    "3650-24ps": DeviceType.MULTILAYER_SWITCH,
    "3650": DeviceType.MULTILAYER_SWITCH,
    # Switches Capa 2
    "2950-24": DeviceType.SWITCH,
    "2950t-24": DeviceType.SWITCH,
    "2960-24tt": DeviceType.SWITCH,
    "2960": DeviceType.SWITCH,
    "switch-pt": DeviceType.SWITCH,
    "switch-pt-empty": DeviceType.SWITCH,
    "bridge-pt": DeviceType.SWITCH,
    # Terminales / PCs
    "pc-pt": DeviceType.PC,
    "laptop-pt": DeviceType.PC,
    "tabletpc-pt": DeviceType.PC,
    "smartphone-pt": DeviceType.PC,
    "pda-pt": DeviceType.PC,
    # Servidores
    "server-pt": DeviceType.SERVER,
    "meraki-server": DeviceType.SERVER,
    # Firewalls
    "5505": DeviceType.FIREWALL,
    "5506-x": DeviceType.FIREWALL,
    "5506": DeviceType.FIREWALL,
    "asa5505": DeviceType.FIREWALL,
    "asa5506": DeviceType.FIREWALL,
    # Wireless / Access Points
    "ap-pt": DeviceType.ACCESS_POINT,
    "ap-pt-a": DeviceType.ACCESS_POINT,
    "ap-pt-ac": DeviceType.ACCESS_POINT,
    "ap-pt-n": DeviceType.ACCESS_POINT,
    "lap-pt": DeviceType.ACCESS_POINT,
    "3702i": DeviceType.ACCESS_POINT,
    "wlc-pt": DeviceType.ACCESS_POINT,
    "2504": DeviceType.ACCESS_POINT,
    "wrt300n": DeviceType.ACCESS_POINT,
    "home-router": DeviceType.ACCESS_POINT,
    # Cloud / WAN
    "cloud-pt": DeviceType.CLOUD,
    "cloud-pt-empty": DeviceType.CLOUD,
    "dsl-modem-pt": DeviceType.CLOUD,
    "cable-modem-pt": DeviceType.CLOUD,
}

CliTransportCallable = Callable[[str, str, bool], Awaitable[str]]


def classify_device_type(model_name: str) -> DeviceType:
    """Clasifica el nombre de modelo de hardware de Packet Tracer en un `DeviceType`.

    Primero realiza una búsqueda O(1) en `_STATIC_DEVICE_MODEL_MAP` y, si no existe
    coincidencia exacta, evalúa prefijos/subcadenas conocidas.

    Args:
        model_name: Nombre de modelo devuelto por `device.getModel()` (ej. '2911', '2960-24TT').

    Returns:
        DeviceType: Categoría normalizada del dispositivo.
    """
    normalized = model_name.strip().lower()
    if not normalized:
        return DeviceType.OTHER

    exact_match = _STATIC_DEVICE_MODEL_MAP.get(normalized)
    if exact_match is not None:
        return exact_match

    if any(token in normalized for token in ("3560", "3650", "multilayer")):
        return DeviceType.MULTILAYER_SWITCH
    if any(token in normalized for token in ("router", "isr", "1941", "2901", "2911", "4321", "4331")):
        return DeviceType.ROUTER
    if any(token in normalized for token in ("switch", "2950", "2960", "catalyst")):
        return DeviceType.SWITCH
    if any(token in normalized for token in ("asa", "5505", "5506", "firewall", "pix")):
        return DeviceType.FIREWALL
    if any(token in normalized for token in ("server",)):
        return DeviceType.SERVER
    if any(token in normalized for token in ("pc", "laptop", "tablet", "phone", "workstation")):
        return DeviceType.PC
    if any(token in normalized for token in ("ap-", "lap-", "wlc", "wireless", "wrt")):
        return DeviceType.ACCESS_POINT
    if any(token in normalized for token in ("cloud", "modem")):
        return DeviceType.CLOUD

    return DeviceType.OTHER


class PacketTracerAPI:
    """Fachada base de interacción con Cisco Packet Tracer (Modo Simulación / Fallback).

    Provee respuestas estructuradas deterministas compatibles con los esquemas
    Pydantic v2 (`TopologyResponse`, `InterfaceStatusResponse`, `RoutingTableResponse`,
    `CliCommandResponse` y `PingResponse`) para validación E2E y desarrollo sin GUI.
    """

    def __init__(self) -> None:
        self._native_runtime = _cisco_pt_runtime

    @property
    def is_native_mode(self) -> bool:
        """Indica si el agente está conectado al runtime interno de Packet Tracer."""
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


class NativePacketTracerAPI(PacketTracerAPI):
    """Implementación de la interfaz hacia el protocolo IPC Nativo de Cisco Packet Tracer (ExApp TCP 38000).

    Arquitectura del Protocolo y Flujo de Conexión (PTMP - Packet Tracer Messaging Protocol):
    -----------------------------------------------------------------------------------------
    1. **Transporte Base**:
       Cisco Packet Tracer expone un servidor IPC local (por defecto en `127.0.0.1:38000`)
       para aplicaciones externas registradas (ExApps).

    2. **Fase 1 - Handshake y Negociación de Sesión (`connect`)**:
       * Apertura de socket TCP hacia `pt_ipc_host:pt_ipc_port` (default `127.0.0.1:38000`).
       * Intercambio de paquetes de negociación PTMP (versión del protocolo, tipo de codificación
         texto/XML/JSON, compresión e intervalos de keepalive).
       * Fase de autenticación ExApp (`ExApp ID` y clave/hash de sesión autorizada en el perfil
         de Packet Tracer bajo *Extensions -> IPC -> Configure Apps*).

    3. **Fase 2 - Invocación de Objetos IPC (`ipc.network()`) y Parsers CLI**:
       * `get_topology`: Recorre jerárquicamente `getDeviceCount()`, `getDeviceAt(i)`,
         `getPortCount()`, `getPortAt(j)` y `getLink()`, clasificando modelos con `_STATIC_DEVICE_MODEL_MAP`.
       * `send_cli_command`: Envía instrucciones a `device.getCommandLine()` y sanitiza la salida.
       * `get_interface_status`: Ejecuta `show ip interface brief` y `show interfaces` vía CLI
         y transforma el texto plano mediante `parse_interface_status`.
       * `get_routing_table`: Ejecuta `show ip route` vía CLI y transforma el resultado con
         `parse_show_ip_route`.
       * `execute_ping`: Ejecuta `ping` vía CLI y extrae métricas ICMP con `parse_ping_output`.
    """

    def __init__(
        self,
        pt_ipc_host: str = "127.0.0.1",
        pt_ipc_port: int = 38000,
        exapp_id: str = "packet-tracer-mcp-exapp",
        timeout_seconds: float | None = None,
        cli_transport: CliTransportCallable | None = None,
        ipc_network_provider: Callable[[], Any] | None = None,
    ) -> None:
        """Inicializa los parámetros de conexión hacia el socket IPC nativo de Packet Tracer.

        Args:
            pt_ipc_host: Dirección IP local del motor IPC de Packet Tracer (default '127.0.0.1').
            pt_ipc_port: Puerto TCP nativo de IPC en Packet Tracer (default 38000).
            exapp_id: Identificador de la External Application (ExApp) registrada en Packet Tracer.
            timeout_seconds: Tiempo límite en segundos para operaciones de socket TCP.
            cli_transport: Función asíncrona opcional para transporte de bajo nivel hacia `CommandLine`.
            ipc_network_provider: Proveedor opcional del objeto `ipc.network()` para pruebas o runtime.
        """
        super().__init__()
        self.pt_ipc_host: str = pt_ipc_host
        self.pt_ipc_port: int = pt_ipc_port
        self.exapp_id: str = exapp_id
        self.timeout_seconds: float = (
            timeout_seconds if timeout_seconds is not None else settings.pt_timeout_seconds
        )
        self._cli_transport: CliTransportCallable | None = cli_transport
        self._ipc_network_provider: Callable[[], Any] | None = ipc_network_provider
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        """Indica si el socket TCP hacia el puerto IPC 38000 se encuentra activo."""
        return self._connected and self._writer is not None and not self._writer.is_closing()

    async def connect(
        self,
        perform_handshake: bool = False,
    ) -> None:
        """Abre la conexión TCP asíncrona hacia el puerto IPC 38000 de Packet Tracer.

        Args:
            perform_handshake: Si es True, invoca el empaquetado de negociación PTMP tras conectar.
        """
        if self.is_connected:
            return

        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.pt_ipc_host, self.pt_ipc_port),
            timeout=self.timeout_seconds,
        )
        self._connected = True

        if perform_handshake:
            await self._perform_ptmp_handshake()

    async def _perform_ptmp_handshake(self) -> None:
        """Empaqueta y negocia las tramas binarias del protocolo PTMP de Cisco Packet Tracer."""
        # TODO(ptmp-protocol): Implementar empaquetado binario de negociación y autenticación ExApp.
        raise NotImplementedError(
            "Pendiente de implementación: Empaquetado de tramas binarias PTMP para autenticación ExApp."
        )

    async def disconnect(self) -> None:
        """Cierra de forma ordenada la sesión PTMP y libera el socket TCP 38000."""
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except OSError:
                pass
            self._writer = None
            self._reader = None
        self._connected = False

    def _get_ipc_network(self) -> Any:
        """Obtiene la instancia de `ipc.network()` desde el proveedor inyectado o `cisco_pt`."""
        if self._ipc_network_provider is not None:
            return self._ipc_network_provider()
        if self._native_runtime is not None:
            return self._native_runtime.ipc().network()
        raise NotImplementedError(
            f"Sesión IPC remota ({self.pt_ipc_host}:{self.pt_ipc_port}) requiere serialización "
            "PTMP o runtime `cisco_pt` activo para acceder a `ipc.network()`."
        )

    async def _execute_raw_cli(
        self,
        hostname: str,
        command: str,
        enable_mode: bool = True,
    ) -> str:
        """Envía un único comando al buffer `CommandLine` del dispositivo en Packet Tracer.

        Si se inyectó `cli_transport` o existe el runtime nativo `cisco_pt`, delega la
        ejecución; de lo contrario, requiere el empaquetado de tramas PTMP en el puerto 38000.
        """
        if self._cli_transport is not None:
            return await self._cli_transport(hostname, command, enable_mode)

        if self._native_runtime is not None:
            device = self._native_runtime.ipc().network().getDevice(hostname)
            if device is None:
                raise ValueError(f"Dispositivo '{hostname}' no encontrado en Packet Tracer.")
            cli = device.getCommandLine()
            if enable_mode:
                cli.enterCommand("enable")
            cli.enterCommand(command)
            return str(cli.getOutput())

        # TODO(ptmp-protocol): Empaquetar invocación IPC remota hacia `getCommandLine()` por socket 38000.
        raise NotImplementedError(
            f"Transporte PTMP TCP ({self.pt_ipc_host}:{self.pt_ipc_port}) pendiente de "
            f"empaquetado binario para ejecutar '{command}' en '{hostname}'."
        )

    async def get_topology(self) -> dict[str, Any]:
        """Recorre jerárquicamente `getDeviceCount()`, `getDeviceAt()`, `getPortCount()` y `getLink()`.

        Clasifica cada `model_name` mediante `_STATIC_DEVICE_MODEL_MAP` / `classify_device_type`
        y deduplica los enlaces bidireccionales entre puertos para construir un diccionario
        100% compatible con `TopologyResponse`.

        Returns:
            dict[str, Any]: Inventario completo de nodos y enlaces físicos activos.
        """
        network = self._get_ipc_network()
        device_count = int(network.getDeviceCount())

        devices: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        seen_links: set[tuple[tuple[str, str], tuple[str, str]]] = set()

        for dev_idx in range(device_count):
            device = network.getDeviceAt(dev_idx)
            if device is None:
                continue

            hostname = str(device.getName()).strip()
            model_name = str(device.getModel()).strip()
            power_on = bool(device.getPower()) if hasattr(device, "getPower") else True
            device_type = classify_device_type(model_name)

            devices.append(
                {
                    "hostname": hostname,
                    "device_type": device_type.value,
                    "model_name": model_name,
                    "power_on": power_on,
                }
            )

            port_count = int(device.getPortCount()) if hasattr(device, "getPortCount") else 0
            for port_idx in range(port_count):
                port = device.getPortAt(port_idx)
                if port is None:
                    continue

                link = port.getLink() if hasattr(port, "getLink") else None
                if link is None:
                    continue

                source_iface = str(port.getName()).strip()
                peer_info = self._extract_peer_from_link(
                    link=link,
                    current_hostname=hostname,
                    current_interface=source_iface,
                )
                if peer_info is None:
                    continue

                target_hostname, target_iface, cable_type, link_status = peer_info

                # Clave canónica ordenada para evitar duplicar el mismo cable desde ambos extremos
                endpoint_a = (hostname, source_iface)
                endpoint_b = (target_hostname, target_iface)
                canonical_pair = (
                    (endpoint_a, endpoint_b)
                    if endpoint_a <= endpoint_b
                    else (endpoint_b, endpoint_a)
                )
                if canonical_pair in seen_links:
                    continue
                seen_links.add(canonical_pair)

                links.append(
                    {
                        "source_hostname": hostname,
                        "source_interface": source_iface,
                        "target_hostname": target_hostname,
                        "target_interface": target_iface,
                        "cable_type": cable_type,
                        "status": link_status.value,
                    }
                )

        return {
            "total_devices": len(devices),
            "total_links": len(links),
            "devices": devices,
            "links": links,
        }

    @staticmethod
    def _extract_peer_from_link(
        link: Any,
        current_hostname: str,
        current_interface: str,
    ) -> tuple[str, str, str, LinkStatus] | None:
        """Extrae el dispositivo e interfaz del extremo remoto a partir de un objeto `Link` IPC."""
        cable_type = (
            str(link.getCableType()).strip()
            if hasattr(link, "getCableType")
            else "copper_straight"
        )
        raw_status = (
            str(link.getStatus()).strip().lower()
            if hasattr(link, "getStatus")
            else LinkStatus.UP.value
        )
        if raw_status == LinkStatus.DOWN.value:
            status = LinkStatus.DOWN
        elif raw_status == LinkStatus.NEGOTIATING.value:
            status = LinkStatus.NEGOTIATING
        else:
            status = LinkStatus.UP

        # Caso 1: El objeto Link expone getPort1()/getPort2() y getDevice1()/getDevice2()
        if hasattr(link, "getDevice1") and hasattr(link, "getDevice2"):
            dev1_name = str(link.getDevice1().getName()).strip()
            port1_name = str(link.getPort1().getName()).strip()
            dev2_name = str(link.getDevice2().getName()).strip()
            port2_name = str(link.getPort2().getName()).strip()

            if (dev1_name, port1_name) == (current_hostname, current_interface):
                return dev2_name, port2_name, cable_type, status
            return dev1_name, port1_name, cable_type, status

        # Caso 2: El objeto Link expone directamente getTargetDeviceName() y getTargetPortName()
        if hasattr(link, "getTargetDeviceName") and hasattr(link, "getTargetPortName"):
            return (
                str(link.getTargetDeviceName()).strip(),
                str(link.getTargetPortName()).strip(),
                cable_type,
                status,
            )

        return None

    async def send_cli_command(
        self,
        hostname: str,
        commands: list[str],
        enable_mode: bool = True,
    ) -> dict[str, Any]:
        """Envía comandos Cisco IOS al `CommandLine` del dispositivo y estructura la respuesta.

        Args:
            hostname: Hostname del dispositivo objetivo.
            commands: Lista secuencial de instrucciones Cisco IOS.
            enable_mode: Si es True, asegura modo EXEC privilegiado antes de ejecutar.

        Returns:
            dict[str, Any]: Diccionario compatible con `CliCommandResponse`.
        """
        results: list[dict[str, Any]] = []

        for cmd in commands:
            raw_out = await self._execute_raw_cli(
                hostname=hostname,
                command=cmd,
                enable_mode=enable_mode,
            )
            cleaned_out = sanitize_console_output(raw_out).strip()
            has_error = bool(_IOS_CLI_ERROR_RE.search(cleaned_out))
            results.append(
                {
                    "command": cmd,
                    "output": cleaned_out,
                    "success": not has_error,
                }
            )

        return {
            "hostname": hostname,
            "enable_mode": enable_mode,
            "results": results,
        }

    async def get_interface_status(self, hostname: str) -> dict[str, Any]:
        """Ejecuta `show ip interface brief` y `show interfaces` y parsea la telemetría.

        Args:
            hostname: Nombre del dispositivo objetivo.

        Returns:
            dict[str, Any]: Diccionario compatible con `InterfaceStatusResponse`.
        """
        cli_response = await self.send_cli_command(
            hostname=hostname,
            commands=["show ip interface brief", "show interfaces"],
            enable_mode=True,
        )
        results = cli_response.get("results", [])
        brief_output = results[0]["output"] if len(results) > 0 else ""
        detail_output = results[1]["output"] if len(results) > 1 else None

        interfaces = parse_interface_status(
            brief_output=brief_output,
            detail_output=detail_output,
        )
        return {
            "hostname": hostname,
            "interfaces": interfaces,
        }

    async def get_routing_table(self, hostname: str) -> dict[str, Any]:
        """Ejecuta `show ip route` en el router y parsea las rutas activas con `parse_show_ip_route`.

        Args:
            hostname: Nombre del router objetivo.

        Returns:
            dict[str, Any]: Diccionario compatible con `RoutingTableResponse`.
        """
        cli_response = await self.send_cli_command(
            hostname=hostname,
            commands=["show ip route"],
            enable_mode=True,
        )
        results = cli_response.get("results", [])
        raw_output = results[0]["output"] if results else ""

        routes = parse_show_ip_route(raw_output)
        return {
            "hostname": hostname,
            "routes": routes,
        }

    async def execute_ping(
        self,
        source_hostname: str,
        destination_ip: str,
        count: int = 4,
    ) -> dict[str, Any]:
        """Ejecuta el comando `ping` en el dispositivo origen y parsea las métricas ICMP.

        Args:
            source_hostname: Hostname del dispositivo desde donde se origina el ping.
            destination_ip: Dirección IPv4 destino.
            count: Cantidad de paquetes solicitados.

        Returns:
            dict[str, Any]: Diccionario compatible con `PingResponse`.
        """
        ping_cmd = f"ping {destination_ip}"
        cli_response = await self.send_cli_command(
            hostname=source_hostname,
            commands=[ping_cmd],
            enable_mode=True,
        )
        results = cli_response.get("results", [])
        raw_output = results[0]["output"] if results else ""

        parsed_stats = parse_ping_output(raw_output)
        return {
            "source_hostname": source_hostname,
            "destination_ip": str(destination_ip),
            **parsed_stats,
        }
