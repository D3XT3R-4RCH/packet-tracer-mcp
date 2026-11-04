"""Modelos de telemetría de dispositivos: interfaces y tablas de enrutamiento (Pydantic v2)."""

import re
from enum import StrEnum
from ipaddress import IPv4Address
from pydantic import BaseModel, ConfigDict, Field, field_validator

HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
MAC_ADDRESS_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})$"
)


def validate_safe_hostname(value: str) -> str:
    """Valida que el hostname siga estándares de red y carezca de caracteres de inyección."""
    cleaned = value.strip()
    if not HOSTNAME_PATTERN.match(cleaned):
        raise ValueError(
            "El hostname contiene caracteres inválidos o potencialmente peligrosos. "
            "Use únicamente caracteres alfanuméricos, guiones, puntos o guiones bajos (máx. 63 caracteres)."
        )
    return cleaned


class OperationalStatus(StrEnum):
    """Estados operativos físicos o lógicos de una interfaz Cisco IOS."""

    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "administratively down"


class RouteProtocol(StrEnum):
    """Códigos de protocolos de enrutamiento en tablas Cisco IOS."""

    CONNECTED = "C"
    LOCAL = "L"
    STATIC = "S"
    RIP = "R"
    OSPF = "O"
    OSPF_IA = "O IA"
    OSPF_E1 = "O E1"
    OSPF_E2 = "O E2"
    EIGRP = "D"
    EIGRP_EX = "D EX"
    BGP = "B"
    OTHER = "OTHER"


class HostnameRequest(BaseModel):
    """Esquema de entrada para consultas basadas en el hostname de un dispositivo."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=63,
        description="Nombre del dispositivo objetivo en Packet Tracer (ej. 'R1', 'SW1').",
    )

    @field_validator("hostname")
    @classmethod
    def check_hostname(cls, v: str) -> str:
        return validate_safe_hostname(v)


class InterfaceStatusItem(BaseModel):
    """Estado detallado de una interfaz individual de un dispositivo."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    interface_name: str = Field(
        ...,
        min_length=1,
        description="Nombre completo de la interfaz (ej. 'GigabitEthernet0/0/0', 'Vlan1').",
    )
    physical_status: OperationalStatus = Field(
        ...,
        description="Estado físico de capa 1 (up, down, administratively down).",
    )
    protocol_status: OperationalStatus = Field(
        ...,
        description="Estado lógico/protocolo de capa 2 (up, down).",
    )
    ip_address: IPv4Address | None = Field(
        default=None,
        description="Dirección IPv4 asignada a la interfaz, o None si no está configurada.",
    )
    subnet_mask: IPv4Address | None = Field(
        default=None,
        description="Máscara de subred IPv4 (ej. '255.255.255.0'), o None si no aplica.",
    )
    mac_address: str | None = Field(
        default=None,
        description="Dirección física MAC en formato Cisco (HHHH.HHHH.HHHH) o IEEE.",
    )

    @field_validator("mac_address")
    @classmethod
    def check_mac_address(cls, v: str | None) -> str | None:
        if v is not None and not MAC_ADDRESS_PATTERN.match(v):
            raise ValueError(
                "Formato de dirección MAC inválido. Se esperaba HHHH.HHHH.HHHH o XX:XX:XX:XX:XX:XX."
            )
        return v


class InterfaceStatusResponse(BaseModel):
    """Respuesta estructurada de la herramienta `get_interface_status`."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(
        ...,
        description="Hostname del dispositivo consultado.",
    )
    interfaces: list[InterfaceStatusItem] = Field(
        default_factory=list,
        description="Lista de interfaces del dispositivo con su estado y direccionamiento.",
    )


class RouteEntry(BaseModel):
    """Entrada individual en la tabla de enrutamiento IPv4 de un router."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    protocol: RouteProtocol = Field(
        ...,
        description="Código del protocolo de enrutamiento (C, L, S, O, D, R, B).",
    )
    network: IPv4Address = Field(
        ...,
        description="Dirección de red destino IPv4.",
    )
    prefix_length: int = Field(
        ...,
        ge=0,
        le=32,
        description="Longitud de prefijo CIDR (0 a 32).",
    )
    next_hop: IPv4Address | None = Field(
        default=None,
        description="Dirección IPv4 del siguiente salto (None si está directamente conectada).",
    )
    outgoing_interface: str | None = Field(
        default=None,
        description="Interfaz de salida asociada a la ruta (ej. 'GigabitEthernet0/1').",
    )
    administrative_distance: int | None = Field(
        default=None,
        ge=0,
        le=255,
        description="Distancia administrativa de la ruta (0-255).",
    )
    metric: int | None = Field(
        default=None,
        ge=0,
        description="Métrica calculada por el protocolo de enrutamiento.",
    )


class RoutingTableResponse(BaseModel):
    """Respuesta estructurada de la herramienta `get_routing_table`."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(
        ...,
        description="Hostname del router consultado.",
    )
    routes: list[RouteEntry] = Field(
        default_factory=list,
        description="Lista de rutas activas en la tabla de enrutamiento (OSPF, conectadas, estáticas, etc.).",
    )

