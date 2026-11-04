"""Esquemas Pydantic v2 para el protocolo de mensajería IPC NDJSON con Packet Tracer."""

from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class IPCStatus(StrEnum):
    """Estado de procesamiento devuelto por el ExApp/Script Module de Packet Tracer."""

    SUCCESS = "success"
    ERROR = "error"


class IPCRequestPayload(BaseModel):
    """Trama de solicitud enviada por socket TCP hacia Packet Tracer."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        ...,
        min_length=1,
        description="Nombre de la acción/herramienta solicitada al módulo IPC.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Diccionario de parámetros validados para la acción.",
    )


class IPCResponsePayload(BaseModel):
    """Trama de respuesta recibida desde Packet Tracer vía NDJSON."""

    model_config = ConfigDict(extra="ignore")

    status: IPCStatus = Field(
        ...,
        description="Resultado de la operación ('success' o 'error').",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Carga útil de datos devuelta por Packet Tracer.",
    )
    error: str | None = Field(
        default=None,
        description="Detalle del error reportado por Packet Tracer cuando status == 'error'.",
    )

