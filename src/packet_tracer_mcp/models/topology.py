"""Modelos de topología y enlaces físicos para Cisco Packet Tracer (Pydantic v2)."""

from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field


class DeviceType(StrEnum):
    """Categorías de dispositivos soportados en la simulación de Packet Tracer."""

    ROUTER = "router"
    SWITCH = "switch"
    MULTILAYER_SWITCH = "multilayer_switch"
    PC = "pc"
    SERVER = "server"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    CLOUD = "cloud"
    OTHER = "other"


class LinkStatus(StrEnum):
    """Estado operativo del enlace físico en la simulación."""

    UP = "up"
    DOWN = "down"
    NEGOTIATING = "negotiating"


class DeviceSummary(BaseModel):
    """Representación resumida de un dispositivo dentro de la topología activa."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Nombre lógico o hostname configurado en el dispositivo (ej. 'R1', 'SW-Core').",
    )
    device_type: DeviceType = Field(
        ...,
        description="Tipo de dispositivo dentro de la simulación (router, switch, pc, etc.).",
    )
    model_name: str = Field(
        ...,
        min_length=1,
        description="Modelo de hardware simulado en Packet Tracer (ej. '2911', '2960-24TT', 'PC-PT').",
    )
    power_on: bool = Field(
        default=True,
        description="Indica si el dispositivo se encuentra encendido eléctricamente.",
    )


class PhysicalLink(BaseModel):
    """Representación de un enlace físico entre dos interfaces de dispositivos."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_hostname: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Hostname del dispositivo origen del enlace.",
    )
    source_interface: str = Field(
        ...,
        min_length=1,
        description="Nombre de la interfaz origen (ej. 'GigabitEthernet0/0').",
    )
    target_hostname: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Hostname del dispositivo destino del enlace.",
    )
    target_interface: str = Field(
        ...,
        min_length=1,
        description="Nombre de la interfaz destino (ej. 'FastEthernet0/1').",
    )
    cable_type: str = Field(
        default="copper_straight",
        description="Tipo de medio físico (copper_straight, copper_cross, fiber, serial).",
    )
    status: LinkStatus = Field(
        default=LinkStatus.UP,
        description="Estado físico del enlace.",
    )


class TopologyResponse(BaseModel):
    """Respuesta estructurada de la herramienta `get_topology`."""

    model_config = ConfigDict(extra="forbid")

    total_devices: int = Field(
        ...,
        ge=0,
        description="Número total de dispositivos detectados en el área de trabajo.",
    )
    total_links: int = Field(
        ...,
        ge=0,
        description="Número total de enlaces físicos activos/conectados.",
    )
    devices: list[DeviceSummary] = Field(
        default_factory=list,
        description="Lista completa de dispositivos en la simulación actual.",
    )
    links: list[PhysicalLink] = Field(
        default_factory=list,
        description="Lista completa de enlaces físicos entre dispositivos.",
    )

