"""Herramientas MCP para el Pilar 1 (Topología y Telemetría)."""

from packet_tracer_mcp.bridge.client import PacketTracerClient
from packet_tracer_mcp.models.devices import (
    HostnameRequest,
    InterfaceStatusResponse,
    RoutingTableResponse,
)
from packet_tracer_mcp.models.topology import TopologyResponse

client = PacketTracerClient()


async def get_topology() -> TopologyResponse:
    """Devuelve la lista completa de dispositivos en la simulación actual (Routers, Switches, PCs) y los enlaces físicos.

    Utilice esta herramienta como primer paso de descubrimiento para conocer todos los nodos
    activos en el espacio de trabajo de Cisco Packet Tracer, sus modelos de hardware, estado
    de encendido y el mapa de interconexiones físicas cableadas entre sus interfaces.

    Returns:
        TopologyResponse: Objeto estructurado con el conteo total, la lista de dispositivos
        (`devices`) y la lista de enlaces físicos (`links`).
    """
    response_data = await client._send_request(
        action="get_topology",
        parameters={},
    )
    return TopologyResponse(**response_data)


async def get_interface_status(hostname: str) -> InterfaceStatusResponse:
    """Obtiene el estado físico/lógico (up/down), dirección IP, máscara y MAC address de las interfaces de un dispositivo específico.

    Permite inspeccionar la telemetría de capa 1, capa 2 y capa 3 de todas las interfaces
    de un router, switch o terminal dentro de la simulación (equivalente estructurado a
    combinar `show ip interface brief` y `show interfaces`).

    Args:
        hostname: Nombre lógico (hostname) del dispositivo en Packet Tracer (ej. 'R1', 'SW-Core').

    Returns:
        InterfaceStatusResponse: Estado detallado de cada interfaz del dispositivo consultado.
    """
    validated = HostnameRequest(hostname=hostname)
    response_data = await client._send_request(
        action="get_interface_status",
        parameters=validated.model_dump(mode="json"),
    )
    return InterfaceStatusResponse(**response_data)


async def get_routing_table(hostname: str) -> RoutingTableResponse:
    """Obtiene la tabla de enrutamiento (rutas OSPF, conectadas, estáticas) de un router.

    Consulta las rutas IPv4 instaladas en la RIB (Routing Information Base) de un router
    o switch multicapa, incluyendo protocolo origen (C, L, S, O, D, R, B), prefijo de red,
    siguiente salto (next-hop), interfaz de salida, distancia administrativa y métrica.

    Args:
        hostname: Nombre lógico (hostname) del router en Packet Tracer (ej. 'R1').

    Returns:
        RoutingTableResponse: Lista estructurada de entradas de enrutamiento activas.
    """
    validated = HostnameRequest(hostname=hostname)
    response_data = await client._send_request(
        action="get_routing_table",
        parameters=validated.model_dump(mode="json"),
    )
    return RoutingTableResponse(**response_data)
