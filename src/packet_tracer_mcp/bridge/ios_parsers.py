"""Parsers de alta eficiencia con expresiones regulares pre-compiladas para salidas CLI Cisco IOS."""

import re
from ipaddress import IPv4Network
from typing import Any

# =====================================================================
# EXPRESIONES REGULARES PRE-COMPILADAS A NIVEL DE MÓDULO (EFICIENCIA)
# =====================================================================

# Artefactos de consola: secuencias de retroceso (char + \x08), paginación --More-- y códigos ANSI
_BACKSPACE_PAIR_RE = re.compile(r"[^\x08]\x08")
_ANSI_AND_MORE_RE = re.compile(r"(\x1b\[[0-9;?]*[A-Za-z]|--More--|\x08+)")

# Encabezado de subred con máscara heredada: ej. "  10.0.0.0/24 is subnetted, 2 subnets"
_SUBNET_HEADER_RE = re.compile(
    r"^\s*(?:\d{1,3}\.){3}\d{1,3}/(\d{1,2})\s+is\s+(?:variably\s+)?subnetted\b",
    re.IGNORECASE,
)

# Rutas con siguiente salto y métrica:
# Ej: "O IA 10.20.30.0/24 [110/2] via 192.168.10.254, 00:05:12, GigabitEthernet0/0"
# Ej: "S*   0.0.0.0/0 [1/0] via 192.168.10.254"
_VIA_ROUTE_RE = re.compile(
    r"^\s*(?P<code_raw>[A-Za-z][A-Za-z0-9*%\s]{0,6}?)\s+"
    r"(?P<network>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<prefix>\d{1,2}))?\s+"
    r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<next_hop>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:,\s*[^,\s]+)*"
    r"(?:,\s*(?P<interface>[A-Za-z][A-Za-z0-9/._-]+))?\s*$"
)

# Rutas directamente conectadas:
# Ej: "C    192.168.10.0/24 is directly connected, GigabitEthernet0/0"
# Ej: "L    192.168.10.1/32 is directly connected, GigabitEthernet0/0"
_CONNECTED_ROUTE_RE = re.compile(
    r"^\s*(?P<code_raw>[A-Za-z][A-Za-z0-9*%\s]{0,6}?)\s+"
    r"(?P<network>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<prefix>\d{1,2}))?\s+"
    r"is\s+directly\s+connected,\s*(?P<interface>[A-Za-z][A-Za-z0-9/._-]+)\s*$",
    re.IGNORECASE,
)

# Resumen de ping en Cisco IOS:
# Ej: "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"
# Ej: "Success rate is 0 percent (0/5)"
_IOS_PING_SUMMARY_RE = re.compile(
    r"Success\s+rate\s+is\s+(?P<rate>\d+(?:\.\d+)?)\s+percent\s*"
    r"\((?P<received>\d+)/(?P<sent>\d+)\)"
    r"(?:,\s*round-trip\s+min/avg/max\s*=\s*"
    r"(?P<min>\d+(?:\.\d+)?)/(?P<avg>\d+(?:\.\d+)?)/(?P<max>\d+(?:\.\d+)?)\s*ms)?",
    re.IGNORECASE,
)

# Resumen de ping en PC-PT (Command Prompt de Packet Tracer):
# Ej: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
_PCPT_PING_PACKETS_RE = re.compile(
    r"Packets:\s*Sent\s*=\s*(?P<sent>\d+),\s*Received\s*=\s*(?P<received>\d+)",
    re.IGNORECASE,
)
_PCPT_PING_RTT_RE = re.compile(
    r"Minimum\s*=\s*(?P<min>\d+(?:\.\d+)?)ms,\s*"
    r"Maximum\s*=\s*(?P<max>\d+(?:\.\d+)?)ms,\s*"
    r"Average\s*=\s*(?P<avg>\d+(?:\.\d+)?)ms",
    re.IGNORECASE,
)

# Línea de `show ip interface brief`:
# Ej: "GigabitEthernet0/0     192.168.10.1    YES manual up                    up"
# Ej: "GigabitEthernet0/1     unassigned      YES unset  administratively down down"
_IP_INT_BRIEF_LINE_RE = re.compile(
    r"^(?P<interface>[A-Za-z][A-Za-z0-9/._-]+)\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|unassigned)\s+"
    r"(?:YES|NO)\s+\S+\s+"
    r"(?P<physical>up|down|administratively\s+down)\s+"
    r"(?P<protocol>up|down)\s*$",
    re.IGNORECASE,
)

# Encabezado de interfaz en `show interfaces`:
# Ej: "GigabitEthernet0/0 is up, line protocol is up (connected)"
# Ej: "GigabitEthernet0/1 is administratively down, line protocol is down (disabled)"
_SHOW_INT_HEADER_RE = re.compile(
    r"^(?P<interface>[A-Za-z][A-Za-z0-9/._-]+)\s+is\s+"
    r"(?P<physical>up|down|administratively\s+down),\s+"
    r"line\s+protocol\s+is\s+(?P<protocol>up|down)\b",
    re.IGNORECASE,
)

# Dirección física MAC en `show interfaces`:
# Ej: "  Hardware is CN Gigabit Ethernet, address is 0001.42a1.0b01 (bia 0001.42a1.0b01)"
_SHOW_INT_MAC_RE = re.compile(
    r"\baddress\s+is\s+(?P<mac>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})\b",
    re.IGNORECASE,
)

# Dirección IPv4 y prefijo CIDR en `show interfaces`:
# Ej: "  Internet address is 192.168.10.1/24"
# Ej: "  Internet address is 192.168.10.1 255.255.255.0"
_SHOW_INT_IPV4_RE = re.compile(
    r"\bInternet\s+address\s+is\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:/(?P<prefix>\d{1,2})|\s+(?P<mask>(?:\d{1,3}\.){3}\d{1,3}))",
    re.IGNORECASE,
)

# Mapa de normalización de códigos de protocolo hacia RouteProtocol
_VALID_PROTOCOL_CODES: frozenset[str] = frozenset(
    {"C", "L", "S", "R", "O", "O IA", "O E1", "O E2", "D", "D EX", "B"}
)

# Caracteres iniciales válidos para filtrado rápido de líneas de ruta
_ROUTE_START_CHARS: frozenset[str] = frozenset("CLSRODBclsrodb")

# Caché pre-calculado de prefijos CIDR (0..32) a máscara decimal punteada
_PREFIX_TO_NETMASK: dict[int, str] = {
    prefix: str(IPv4Network(f"0.0.0.0/{prefix}").netmask) for prefix in range(33)
}


def sanitize_console_output(raw_output: str) -> str:
    """Limpia artefactos de terminal de Packet Tracer (`\\r`, retrocesos `\\x08`, `--More--`).

    Args:
        raw_output: Cadena cruda proveniente del buffer CLI de Packet Tracer.

    Returns:
        str: Cadena normalizada con saltos de línea `\\n` limpios.
    """
    if not raw_output:
        return ""

    text = raw_output.replace("\r\n", "\n").replace("\r", "\n")

    # Resolver secuencias de retroceso (backspace) iterativamente si existen
    while "\x08" in text:
        updated = _BACKSPACE_PAIR_RE.sub("", text)
        if updated == text:
            break
        text = updated

    return _ANSI_AND_MORE_RE.sub("", text)


def _normalize_protocol_code(raw_code: str) -> str:
    """Normaliza el código de protocolo de Cisco IOS (ej. 'S*' -> 'S', 'O   IA' -> 'O IA')."""
    cleaned = " ".join(raw_code.replace("*", "").replace("%", "").upper().split())
    if cleaned in _VALID_PROTOCOL_CODES:
        return cleaned
    first_token = cleaned.split()[0] if cleaned else ""
    if first_token in _VALID_PROTOCOL_CODES:
        return first_token
    return "OTHER"


def _normalize_operational_status(raw_status: str) -> str:
    """Normaliza el estado físico/protocolo a minúsculas con espacios simples."""
    return " ".join(raw_status.lower().split())


def parse_show_ip_route(raw_output: str) -> list[dict[str, Any]]:
    """Extrae las entradas de la tabla de enrutamiento desde la salida de `show ip route`.

    Procesa la entrada línea por línea en una sola pasada con descarte rápido (`continue`)
    para encabezados, líneas vacías y leyendas de códigos, manteniendo consumo mínimo de memoria.

    Args:
        raw_output: Salida textual del comando `show ip route` en Cisco IOS.

    Returns:
        list[dict[str, Any]]: Lista de diccionarios compatibles con `RouteEntry`.
    """
    sanitized = sanitize_console_output(raw_output)
    if not sanitized:
        return []

    routes: list[dict[str, Any]] = []
    inherited_prefix: int = 24

    for raw_line in sanitized.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Verificar si es un encabezado de subred que define prefijo heredado
        if line[0].isdigit():
            header_match = _SUBNET_HEADER_RE.match(line)
            if header_match:
                inherited_prefix = int(header_match.group(1))
            continue

        # Descarte rápido: si no inicia con una letra de protocolo válida o contiene leyenda ':'
        if line[0] not in _ROUTE_START_CHARS or " - " in line or line.startswith("Codes:"):
            continue
        if line.startswith("Gateway of last resort"):
            continue

        # 1. Intentar match con ruta dinámica/estática vía next-hop ([AD/Metric] via ...)
        via_match = _VIA_ROUTE_RE.match(line)
        if via_match:
            prefix_str = via_match.group("prefix")
            prefix_len = int(prefix_str) if prefix_str is not None else inherited_prefix
            routes.append(
                {
                    "protocol": _normalize_protocol_code(via_match.group("code_raw")),
                    "network": via_match.group("network"),
                    "prefix_length": prefix_len,
                    "next_hop": via_match.group("next_hop"),
                    "outgoing_interface": via_match.group("interface"),
                    "administrative_distance": int(via_match.group("ad")),
                    "metric": int(via_match.group("metric")),
                }
            )
            continue

        # 2. Intentar match con ruta directamente conectada (is directly connected, <iface>)
        conn_match = _CONNECTED_ROUTE_RE.match(line)
        if conn_match:
            prefix_str = conn_match.group("prefix")
            prefix_len = int(prefix_str) if prefix_str is not None else inherited_prefix
            routes.append(
                {
                    "protocol": _normalize_protocol_code(conn_match.group("code_raw")),
                    "network": conn_match.group("network"),
                    "prefix_length": prefix_len,
                    "next_hop": None,
                    "outgoing_interface": conn_match.group("interface"),
                    "administrative_distance": 0,
                    "metric": 0,
                }
            )

    return routes


def parse_interface_status(
    brief_output: str = "",
    detail_output: str | None = None,
) -> list[dict[str, Any]]:
    """Extrae la telemetría de interfaces desde `show ip interface brief` y/o `show interfaces`.

    Procesa línea por línea utilizando expresiones regulares pre-compiladas. Si se provee
    únicamente `brief_output`, extrae estado físico/lógico e IPv4; si se complementa con
    `detail_output` (`show interfaces`) —o si solo se provee `detail_output`—, enriquece
    cada interfaz con su máscara de subred (`subnet_mask`) y dirección física (`mac_address`).

    Args:
        brief_output: Salida textual de `show ip interface brief`.
        detail_output: Salida textual opcional de `show interfaces` para extraer MAC y máscara.

    Returns:
        list[dict[str, Any]]: Lista de diccionarios compatibles con `InterfaceStatusItem`.
    """
    interfaces_by_name: dict[str, dict[str, Any]] = {}

    # 1. Pasada rápida sobre `show ip interface brief` (si fue provisto)
    sanitized_brief = sanitize_console_output(brief_output)
    if sanitized_brief:
        for raw_line in sanitized_brief.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Interface") or "#" in line or ">" in line:
                continue

            match = _IP_INT_BRIEF_LINE_RE.match(line)
            if not match:
                continue

            iface_name = match.group("interface")
            raw_ip = match.group("ip")
            ip_addr = None if raw_ip.lower() == "unassigned" else raw_ip

            interfaces_by_name[iface_name] = {
                "interface_name": iface_name,
                "physical_status": _normalize_operational_status(match.group("physical")),
                "protocol_status": _normalize_operational_status(match.group("protocol")),
                "ip_address": ip_addr,
                "subnet_mask": None,
                "mac_address": None,
            }

    # 2. Pasada ligera sobre `show interfaces` para complementar MAC, máscara (o descubrir interfaces)
    sanitized_detail = sanitize_console_output(detail_output or "")
    if sanitized_detail:
        current_iface: dict[str, Any] | None = None

        for raw_line in sanitized_detail.splitlines():
            if not raw_line.strip():
                continue

            # Líneas sin sangría inicial suelen ser encabezados de interfaz ("GigabitEthernet0/0 is ...")
            if not raw_line[0].isspace():
                header_match = _SHOW_INT_HEADER_RE.match(raw_line.strip())
                if header_match:
                    iface_name = header_match.group("interface")
                    phys = _normalize_operational_status(header_match.group("physical"))
                    proto = _normalize_operational_status(header_match.group("protocol"))

                    if iface_name in interfaces_by_name:
                        current_iface = interfaces_by_name[iface_name]
                        current_iface["physical_status"] = phys
                        current_iface["protocol_status"] = proto
                    else:
                        current_iface = {
                            "interface_name": iface_name,
                            "physical_status": phys,
                            "protocol_status": proto,
                            "ip_address": None,
                            "subnet_mask": None,
                            "mac_address": None,
                        }
                        interfaces_by_name[iface_name] = current_iface
                continue

            # Líneas indentadas: solo inspeccionar si tenemos una interfaz activa y contienen palabras clave
            if current_iface is None:
                continue

            if "address is" in raw_line:
                if current_iface["mac_address"] is None:
                    mac_match = _SHOW_INT_MAC_RE.search(raw_line)
                    if mac_match:
                        current_iface["mac_address"] = mac_match.group("mac").upper()
                        continue

                ip_match = _SHOW_INT_IPV4_RE.search(raw_line)
                if ip_match:
                    current_iface["ip_address"] = ip_match.group("ip")
                    prefix_str = ip_match.group("prefix")
                    mask_str = ip_match.group("mask")
                    if prefix_str is not None:
                        current_iface["subnet_mask"] = _PREFIX_TO_NETMASK.get(int(prefix_str))
                    elif mask_str is not None:
                        current_iface["subnet_mask"] = mask_str

    return list(interfaces_by_name.values())


def parse_ping_output(raw_output: str) -> dict[str, Any]:
    """Extrae estadísticas de paquetes y RTT desde la salida de `ping` en Cisco IOS o PC-PT.

    Args:
        raw_output: Salida textual del comando `ping`.

    Returns:
        dict[str, Any]: Diccionario con `packets_sent`, `packets_received`,
        `success_rate_percent`, `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms` y `raw_output`.

    Raises:
        ValueError: Si la salida no contiene un bloque de estadísticas de ping reconocible.
    """
    sanitized = sanitize_console_output(raw_output)

    # 1. Formato estándar Cisco IOS ("Success rate is X percent (rx/tx)...")
    ios_match = _IOS_PING_SUMMARY_RE.search(sanitized)
    if ios_match:
        sent = int(ios_match.group("sent"))
        received = int(ios_match.group("received"))
        rate = float(ios_match.group("rate"))
        min_str = ios_match.group("min")
        avg_str = ios_match.group("avg")
        max_str = ios_match.group("max")

        return {
            "packets_sent": sent,
            "packets_received": received,
            "success_rate_percent": rate,
            "rtt_min_ms": float(min_str) if min_str is not None else None,
            "rtt_avg_ms": float(avg_str) if avg_str is not None else None,
            "rtt_max_ms": float(max_str) if max_str is not None else None,
            "raw_output": sanitized.strip(),
        }

    # 2. Formato alternativo PC-PT ("Packets: Sent = X, Received = Y...")
    pc_match = _PCPT_PING_PACKETS_RE.search(sanitized)
    if pc_match:
        sent = int(pc_match.group("sent"))
        received = int(pc_match.group("received"))
        rate = (received / sent * 100.0) if sent > 0 else 0.0

        rtt_match = _PCPT_PING_RTT_RE.search(sanitized)
        return {
            "packets_sent": sent,
            "packets_received": received,
            "success_rate_percent": round(rate, 2),
            "rtt_min_ms": float(rtt_match.group("min")) if rtt_match else None,
            "rtt_avg_ms": float(rtt_match.group("avg")) if rtt_match else None,
            "rtt_max_ms": float(rtt_match.group("max")) if rtt_match else None,
            "raw_output": sanitized.strip(),
        }

    raise ValueError(
        "No se pudo extraer el resumen estadístico de la salida del comando ping."
    )
