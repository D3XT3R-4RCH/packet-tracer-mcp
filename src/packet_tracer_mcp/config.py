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
        description="Puerto TCP del servicio IPC/ExApp en Packet Tracer.",
    )
    pt_timeout_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=120.0,
        validation_alias="PT_TIMEOUT_SECONDS",
        description="Tiempo máximo de espera en segundos para operaciones de socket TCP.",
    )


settings = Settings()

