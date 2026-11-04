"""Herramientas MCP para el Pilar 2 (Configuración CLI) y Pilar 3 (Diagnóstico)."""

from packet_tracer_mcp.bridge.client import PacketTracerClient
from packet_tracer_mcp.models.commands import (
    CliCommandRequest,
    CliCommandResponse,
    PingRequest,
    PingResponse,
)

client = PacketTracerClient()


async def send_cli_command(
    hostname: str,
    commands: list[str],
    enable_mode: bool = True,
) -> CliCommandResponse:
    """Envía un comando o lista de comandos Cisco IOS a un dispositivo y devuelve la salida.

    Ejecuta secuencialmente instrucciones de consola Cisco IOS sobre el dispositivo indicado.
    Todos los comandos pasan por una validación estricta de seguridad (Pydantic v2) que
    bloquea metacaracteres de inyección y binarios del sistema operativo anfitrión
    (como `bash`, `sh`, `rm`, `wget`, `curl`, `powershell`, etc.).

    Args:
        hostname: Hostname del dispositivo Cisco IOS destino (ej. 'R1', 'SW1').
        commands: Lista ordenada de comandos Cisco IOS a ejecutar (ej. ['configure terminal', 'interface Gi0/0', 'no shutdown']).
        enable_mode: Si es True (por defecto), garantiza que la sesión esté en modo EXEC privilegiado antes de enviar los comandos.

    Returns:
        CliCommandResponse: Salida detallada producida por la consola IOS para cada comando enviado.
    """
    validated = CliCommandRequest(
        hostname=hostname,
        commands=commands,
        enable_mode=enable_mode,
    )
    response_data = await client._send_request(
        action="send_cli_command",
        parameters=validated.model_dump(mode="json"),
    )
    return CliCommandResponse(**response_data)


async def execute_ping(
    source_hostname: str,
    destination_ip: str,
    count: int = 4,
) -> PingResponse:
    """Ejecuta un comando ping desde un dispositivo origen hacia una IP destino y devuelve el porcentaje de éxito.

    Permite verificar la conectividad IPv4 extremo a extremo en la topología simulada
    mediante el envío de paquetes ICMP Echo Request y el cálculo de paquetes recibidos,
    porcentaje de éxito y tiempos de ida y vuelta (RTT min/avg/max).

    Args:
        source_hostname: Hostname del dispositivo desde el cual se ejecuta la prueba (ej. 'PC1', 'R1').
        destination_ip: Dirección IPv4 destino válida (ej. '192.168.1.1').
        count: Cantidad de paquetes ICMP a enviar (por defecto 4, mínimo 1, máximo 10).

    Returns:
        PingResponse: Estadísticas de paquetes enviados/recibidos, porcentaje de éxito y RTT.
    """
    validated = PingRequest(
        source_hostname=source_hostname,
        destination_ip=destination_ip,
        count=count,
    )
    response_data = await client._send_request(
        action="execute_ping",
        parameters=validated.model_dump(mode="json"),
    )
    return PingResponse(**response_data)
