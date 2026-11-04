"""Modelos de configuración CLI y diagnóstico con validación anti-inyección (Pydantic v2)."""

import re
from ipaddress import IPv4Address
from pydantic import BaseModel, ConfigDict, Field, field_validator
from packet_tracer_mcp.models.devices import validate_safe_hostname

# Lista negra estricta de binarios/comandos de SO anfitrión y shells no permitidos
FORBIDDEN_OS_COMMANDS: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "rm",
        "del",
        "erase",
        "rmdir",
        "wget",
        "curl",
        "invoke-webrequest",
        "iwr",
        "nc",
        "netcat",
        "ncat",
        "python",
        "python3",
        "perl",
        "ruby",
        "php",
        "node",
        "chmod",
        "chown",
        "sudo",
        "su",
        "cat",
        "type",
        "eval",
        "exec",
        "tclsh",
        "ios.sh",
        "shell",
        "scp",
        "sftp",
        "ftp",
        "tftp",
        "nmap",
    }
)

# Patrones de metacaracteres de inyección de comandos de sistema operativo
SHELL_INJECTION_PATTERN = re.compile(r"(;|&&|\|\||`|\$\(|\$\{|>|<|\x00|\r|\n)")

# Prefijos válidos de comandos de consola Cisco IOS (modo EXEC / configuración)
VALID_IOS_FIRST_TOKEN_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")


class CliCommandRequest(BaseModel):
    """Esquema de entrada validado para `send_cli_command` con protección anti-inyección."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=63,
        description="Hostname del dispositivo Cisco IOS destino (ej. 'R1', 'SW1').",
    )
    commands: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Lista secuencial de comandos Cisco IOS a ejecutar en el dispositivo.",
    )
    enable_mode: bool = Field(
        default=True,
        description="Si es True, eleva la sesión a modo EXEC privilegiado ('enable') antes de ejecutar.",
    )

    @field_validator("hostname")
    @classmethod
    def check_hostname(cls, v: str) -> str:
        return validate_safe_hostname(v)

    @field_validator("commands")
    @classmethod
    def validate_ios_commands(cls, commands: list[str]) -> list[str]:
        if not commands:
            raise ValueError("La lista de comandos no puede estar vacía.")

        sanitized_commands: list[str] = []
        for idx, raw_cmd in enumerate(commands):
            cmd = raw_cmd.strip()
            if not cmd:
                raise ValueError(f"El comando en la posición {idx} está vacío.")

            if SHELL_INJECTION_PATTERN.search(cmd):
                raise ValueError(
                    f"Rechazado por seguridad (Anti-Inyección): El comando en la posición {idx} "
                    "contiene metacaracteres de encadenamiento o redirección de shell no permitidos."
                )

            tokens = cmd.split()
            first_token = tokens[0].lower()

            # Verificar si el primer token o ruta invoca un comando de sistema operativo
            normalized_root = first_token.split("/")[-1].split("\\")[-1]
            if first_token in FORBIDDEN_OS_COMMANDS or normalized_root in FORBIDDEN_OS_COMMANDS:
                raise ValueError(
                    f"Rechazado por seguridad (Anti-Inyección): '{tokens[0]}' es un comando "
                    "de sistema operativo anfitrión prohibido en consolas Cisco IOS."
                )

            # Impedir rutas de sistema de archivos del host (/bin/..., C:\...)
            if "/" in first_token or "\\" in first_token or ":" in first_token:
                raise ValueError(
                    f"Rechazado por seguridad: El comando '{tokens[0]}' parece una ruta de sistema "
                    "y no una instrucción válida de Cisco IOS."
                )

            if not VALID_IOS_FIRST_TOKEN_PATTERN.match(tokens[0]):
                raise ValueError(
                    f"Comando inválido en la posición {idx}: '{tokens[0]}' no cumple la sintaxis "
                    "de un verbo de comando Cisco IOS."
                )

            sanitized_commands.append(cmd)

        return sanitized_commands


class CliCommandOutputItem(BaseModel):
    """Resultado individual de la ejecución de un comando Cisco IOS."""

    model_config = ConfigDict(extra="forbid")

    command: str = Field(
        ...,
        description="Comando Cisco IOS ejecutado.",
    )
    output: str = Field(
        ...,
        description="Salida de texto devuelta por la consola CLI del dispositivo.",
    )
    success: bool = Field(
        default=True,
        description="False si la consola IOS devolvió un error sintáctico ('% Invalid input...').",
    )


class CliCommandResponse(BaseModel):
    """Respuesta estructurada de la herramienta `send_cli_command`."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(
        ...,
        description="Hostname del dispositivo donde se ejecutaron los comandos.",
    )
    enable_mode: bool = Field(
        ...,
        description="Indica si la sesión se ejecutó en modo privilegiado (enable).",
    )
    results: list[CliCommandOutputItem] = Field(
        default_factory=list,
        description="Resultados secuenciales por cada comando enviado.",
    )


class PingRequest(BaseModel):
    """Esquema de entrada validado para la herramienta `execute_ping`."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_hostname: str = Field(
        ...,
        min_length=1,
        max_length=63,
        description="Hostname del dispositivo desde el cual se origina el ping.",
    )
    destination_ip: IPv4Address = Field(
        ...,
        description="Dirección IPv4 destino hacia la cual se envían los paquetes ICMP Echo.",
    )
    count: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Cantidad de paquetes ICMP a enviar (por defecto 4, mínimo 1, máximo 10).",
    )

    @field_validator("source_hostname")
    @classmethod
    def check_source_hostname(cls, v: str) -> str:
        return validate_safe_hostname(v)


class PingResponse(BaseModel):
    """Respuesta estructurada de la herramienta de diagnóstico `execute_ping`."""

    model_config = ConfigDict(extra="forbid")

    source_hostname: str = Field(
        ...,
        description="Hostname del dispositivo origen.",
    )
    destination_ip: IPv4Address = Field(
        ...,
        description="Dirección IPv4 destino evaluada.",
    )
    packets_sent: int = Field(
        ...,
        ge=1,
        le=10,
        description="Número de paquetes ICMP Echo enviados.",
    )
    packets_received: int = Field(
        ...,
        ge=0,
        le=10,
        description="Número de respuestas ICMP Echo Reply recibidas.",
    )
    success_rate_percent: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Porcentaje de éxito de la prueba de conectividad (0.0 a 100.0).",
    )
    rtt_min_ms: float | None = Field(
        default=None,
        ge=0.0,
        description="Tiempo de ida y vuelta mínimo en milisegundos (si hubo respuesta).",
    )
    rtt_avg_ms: float | None = Field(
        default=None,
        ge=0.0,
        description="Tiempo de ida y vuelta promedio en milisegundos (si hubo respuesta).",
    )
    rtt_max_ms: float | None = Field(
        default=None,
        ge=0.0,
        description="Tiempo de ida y vuelta máximo en milisegundos (si hubo respuesta).",
    )
    raw_output: str = Field(
        default="",
        description="Salida textual completa del comando ping en la consola del dispositivo.",
    )

