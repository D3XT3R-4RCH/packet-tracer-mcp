"""Agente servidor TCP asíncrono (NDJSON) del lado de Cisco Packet Tracer."""

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any
from pydantic import ValidationError
from packet_tracer_mcp.bridge.pt_api import NativePacketTracerAPI, PacketTracerAPI
from packet_tracer_mcp.config import settings
from packet_tracer_mcp.models.ipc import IPCRequestPayload, IPCResponsePayload, IPCStatus

logger = logging.getLogger(__name__)

ActionHandler = Callable[..., Coroutine[Any, Any, dict[str, Any]]]


class PacketTracerAgentServer:
    """Servidor TCP asíncrono que escucha peticiones NDJSON y las despacha a `PacketTracerAPI`."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        api: PacketTracerAPI | None = None,
    ) -> None:
        self.host: str = host if host is not None else settings.pt_host
        self.port: int = port if port is not None else settings.pt_port
        if api is not None:
            self.api: PacketTracerAPI = api
        elif settings.pt_use_native_ipc:
            self.api = NativePacketTracerAPI(
                pt_ipc_host=self.host,
                pt_ipc_port=settings.pt_native_port,
                exapp_id=settings.pt_exapp_id,
            )
        else:
            self.api = PacketTracerAPI()
        self._server: asyncio.AbstractServer | None = None
        self._ready_event: asyncio.Event = asyncio.Event()

        self._dispatch_map: dict[str, ActionHandler] = {
            "get_topology": self.api.get_topology,
            "get_interface_status": self.api.get_interface_status,
            "get_routing_table": self.api.get_routing_table,
            "send_cli_command": self.api.send_cli_command,
            "execute_ping": self.api.execute_ping,
        }

    @property
    def bound_port(self) -> int:
        """Devuelve el puerto TCP real asignado al servidor (útil cuando `port=0` efímero)."""
        if self._server and self._server.sockets:
            sockname = self._server.sockets[0].getsockname()
            return int(sockname[1])
        return self.port

    async def wait_until_ready(self, timeout: float = 5.0) -> None:
        """Espera hasta que el servidor TCP esté activo y aceptando conexiones."""
        await asyncio.wait_for(self._ready_event.wait(), timeout=timeout)

    async def _process_raw_line(self, raw_line: bytes) -> IPCResponsePayload:
        """Decodifica una línea NDJSON, invoca el método en `PacketTracerAPI` y construye la respuesta."""
        try:
            decoded_str = raw_line.decode("utf-8").strip()
            payload_dict = json.loads(decoded_str)
            request = IPCRequestPayload.model_validate(payload_dict)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            return IPCResponsePayload(
                status=IPCStatus.ERROR,
                data={},
                error=f"Solicitud NDJSON inválida: {exc}",
            )

        handler = self._dispatch_map.get(request.action)
        if handler is None:
            return IPCResponsePayload(
                status=IPCStatus.ERROR,
                data={},
                error=f"Acción no soportada por el agente PT: '{request.action}'.",
            )

        try:
            result_data = await handler(**request.parameters)
            return IPCResponsePayload(
                status=IPCStatus.SUCCESS,
                data=result_data,
            )
        except TypeError as exc:
            return IPCResponsePayload(
                status=IPCStatus.ERROR,
                data={},
                error=f"Parámetros inválidos para la acción '{request.action}': {exc}",
            )
        except Exception as exc:
            return IPCResponsePayload(
                status=IPCStatus.ERROR,
                data={},
                error=f"Error interno ejecutando '{request.action}': {exc}",
            )

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Atiende una conexión entrante del servidor MCP leyendo líneas NDJSON."""
        try:
            while not reader.at_eof():
                raw_line = await reader.readline()
                if not raw_line:
                    break

                response_payload = await self._process_raw_line(raw_line)
                response_bytes = (
                    json.dumps(
                        response_payload.model_dump(mode="json", exclude_none=True),
                        ensure_ascii=False,
                    )
                    + "\n"
                ).encode("utf-8")

                writer.write(response_bytes)
                await writer.drain()
        except OSError:
            logger.debug("Conexión TCP cerrada de forma abrupta por el cliente.")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        """Inicia el servidor TCP asíncrono en `PT_HOST:PT_PORT` y mantiene el bucle activo."""
        self._ready_event.clear()
        self._server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        self.port = self.bound_port
        self._ready_event.set()
        logger.info("Agente IPC de Packet Tracer escuchando en %s:%s", self.host, self.port)
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("Servidor Agente IPC cancelado limpiamente.")

    async def stop(self) -> None:
        """Detiene de forma limpia el servidor TCP asíncrono."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self._ready_event.clear()


def main() -> None:
    """Punto de entrada CLI para iniciar el Agente Puente de Packet Tracer."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    agent = PacketTracerAgentServer()
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
