"""Cliente asíncrono IPC TCP (NDJSON) para comunicación con Cisco Packet Tracer."""

import asyncio
import json
from typing import Any
from pydantic import ValidationError
from packet_tracer_mcp.config import settings
from packet_tracer_mcp.models.ipc import IPCRequestPayload, IPCResponsePayload, IPCStatus


class PacketTracerIPCError(Exception):
    """Excepción base para errores de comunicación o ejecución IPC con Packet Tracer."""


class PacketTracerConnectionError(PacketTracerIPCError):
    """Error cuando el socket TCP de Packet Tracer rechaza o pierde la conexión."""


class PacketTracerTimeoutError(PacketTracerIPCError):
    """Error cuando Packet Tracer excede el tiempo máximo de respuesta configurado."""


class PacketTracerProtocolError(PacketTracerIPCError):
    """Error cuando la respuesta recibida no cumple el formato NDJSON esperado o reporta fallo."""


class PacketTracerClient:
    """Cliente TCP asíncrono para enviar comandos y recibir telemetría vía ExApp/IPC en formato NDJSON."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.host: str = host if host is not None else settings.pt_host
        self.port: int = port if port is not None else settings.pt_port
        self.timeout_seconds: float = (
            timeout_seconds if timeout_seconds is not None else settings.pt_timeout_seconds
        )

    async def _send_request(
        self,
        action: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Envía una trama JSON delimitada por salto de línea (NDJSON) y retorna el diccionario `data`.

        Args:
            action: Nombre de la herramienta o acción IPC a invocar.
            parameters: Diccionario con los parámetros ya validados por Pydantic.

        Returns:
            dict[str, Any]: Contenido del campo `data` de la respuesta de Packet Tracer.

        Raises:
            PacketTracerConnectionError: Si el servicio IPC en Packet Tracer no está disponible.
            PacketTracerTimeoutError: Si la conexión o lectura supera `PT_TIMEOUT_SECONDS`.
            PacketTracerProtocolError: Si el JSON es inválido o Packet Tracer devuelve `status == "error"`.
        """
        request_obj = IPCRequestPayload(
            action=action,
            parameters=parameters or {},
        )
        payload_bytes = (
            json.dumps(request_obj.model_dump(mode="json"), ensure_ascii=False) + "\n"
        ).encode("utf-8")

        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout_seconds,
            )

            writer.write(payload_bytes)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout_seconds)

            raw_line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout_seconds,
            )
        except ConnectionRefusedError as exc:
            raise PacketTracerConnectionError(
                f"Conexión rechazada hacia el servicio IPC de Packet Tracer en "
                f"{self.host}:{self.port}. Verifique que Packet Tracer y el módulo ExApp estén activos."
            ) from exc
        except TimeoutError as exc:
            raise PacketTracerTimeoutError(
                f"Tiempo de espera agotado ({self.timeout_seconds}s) esperando respuesta "
                f"de Packet Tracer ({self.host}:{self.port}) para la acción '{action}'."
            ) from exc
        except OSError as exc:
            raise PacketTracerConnectionError(
                f"Fallo de red/socket al comunicar con Packet Tracer en {self.host}:{self.port} "
                f"durante la acción '{action}'."
            ) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        if not raw_line:
            raise PacketTracerProtocolError(
                f"El socket IPC de Packet Tracer cerró la conexión sin enviar datos "
                f"para la acción '{action}'."
            )

        try:
            decoded_json = json.loads(raw_line.decode("utf-8").strip())
            response = IPCResponsePayload.model_validate(decoded_json)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise PacketTracerProtocolError(
                f"Respuesta NDJSON malformada o incompatible recibida desde Packet Tracer "
                f"en la acción '{action}'."
            ) from exc

        if response.status == IPCStatus.ERROR:
            error_detail = response.error or response.data.get("message", "Error desconocido en Packet Tracer.")
            raise PacketTracerProtocolError(
                f"Packet Tracer reportó un error al ejecutar '{action}': {error_detail}"
            )

        return response.data

