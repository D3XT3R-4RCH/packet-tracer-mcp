"""Configuración centralizada del servidor MCP mediante Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variables de entorno para la conexión IPC TCP con Cisco Packet Tracer."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    pt_host: str = Field(
        default="127.0.0.1",
        validation_alias="PT_HOST",
        description="Dirección IP o hostname local del socket IPC/ExApp de Packet Tracer.",
    )
    pt_port: int = Field(
        default=39000,
        ge=1,
        le=65535,
        validation_alias="PT_PORT",
        description="Puerto TCP del servicio puente NDJSON del Agente Packet Tracer.",
    )
    pt_timeout_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=120.0,
        validation_alias="PT_TIMEOUT_SECONDS",
        description="Tiempo máximo de espera en segundos para operaciones de socket TCP.",
    )
    pt_use_native_ipc: bool = Field(
        default=False,
        validation_alias="PT_USE_NATIVE_IPC",
        description="Interruptor para alternar entre simulación (False) e IPC nativo ExApp (True).",
    )
    pt_native_port: int = Field(
        default=38000,
        ge=1,
        le=65535,
        validation_alias="PT_NATIVE_PORT",
        description="Puerto TCP nativo del motor IPC/ExApp en Cisco Packet Tracer (default 38000).",
    )
    pt_exapp_id: str = Field(
        default="packet-tracer-mcp-exapp",
        min_length=1,
        validation_alias="PT_EXAPP_ID",
        description="Identificador registrado de la External Application (ExApp) en Packet Tracer.",
    )


settings = Settings()
