# Packet Tracer MCP Server (`packet-tracer-mcp`)

Servidor **Model Context Protocol (MCP)** desarrollado en **Python 3.11+** con `FastMCP` y `Pydantic v2` para automatización, telemetría de red, configuración CLI Cisco IOS y diagnóstico sobre **Cisco Packet Tracer**.

---

## Arquitectura del Sistema

El proyecto sigue una arquitectura desacoplada de dos procesos comunicados mediante sockets TCP locales utilizando tramas **NDJSON** (Newline Delimited JSON):

```text
+-----------------------+        MCP (stdio)        +-------------------------+
|   Cliente LLM / MCP   | <-----------------------> |    packet-tracer-mcp    |
| (Claude Desktop, IDE) |                           |  (FastMCP + Pydantic)   |
+-----------------------+                           +------------+------------+
                                                                 |
                                                       TCP Socket (NDJSON)
                                                      PT_HOST:PT_PORT (39000)
                                                                 |
                                                    +------------v------------+
                                                    |   packet-tracer-agent   |
                                                    | (PacketTracerAgentServer|
                                                    |    + PacketTracerAPI)   |
                                                    +------------+------------+
                                                                 |
                                                        IPC Nativo / ExApp
                                                    +------------v------------+
                                                    |  Cisco Packet Tracer    |
                                                    +-------------------------+
```

1. **`packet-tracer-mcp` (`src/packet_tracer_mcp/server.py`)**:
   * Actúa como servidor **FastMCP** frente al cliente LLM (vía `stdio`).
   * Valida estrictamente todas las entradas y salidas con **Pydantic v2**, incluyendo protección activa **Anti-Inyección de Comandos de SO** en `CliCommandRequest` y validación de direccionamiento IPv4/hostnames.
   * Utiliza `PacketTracerClient` (`bridge/client.py`) para enviar peticiones asíncronas `{"action": "<tool_name>", "parameters": {...}}\n` al agente puente.

2. **`packet-tracer-agent` (`src/packet_tracer_mcp/bridge/pt_agent.py`)**:
   * Actúa como servidor TCP asíncrono (`asyncio.start_server`) escuchando en `PT_HOST:PT_PORT` (por defecto `127.0.0.1:39000`).
   * Despacha cada acción solicitada hacia la fachada `PacketTracerAPI` (`bridge/pt_api.py`), la cual interactúa con el entorno de simulación y devuelve respuestas estructuradas `{"status": "success", "data": {...}}\n`.

---

## Herramientas MCP Expuestas (Tools)

| Pilar | Herramienta | Descripción |
| :--- | :--- | :--- |
| **1. Topología y Telemetría** | `get_topology` | Devuelve el inventario completo de dispositivos (`routers`, `switches`, `pcs`) y enlaces físicos activos. |
| **1. Topología y Telemetría** | `get_interface_status` | Obtiene el estado físico/protocolo (`up`/`down`), IPv4, máscara y dirección MAC de las interfaces de un nodo. |
| **1. Topología y Telemetría** | `get_routing_table` | Obtiene la tabla de enrutamiento IPv4 (`C`, `L`, `S`, `O`, `D`, `R`, `B`) de un router o switch multicapa. |
| **2. Configuración CLI** | `send_cli_command` | Ejecuta secuencias de comandos Cisco IOS validadas contra inyección de comandos del sistema operativo anfitrión. |
| **3. Diagnóstico** | `execute_ping` | Ejecuta pruebas ICMP Echo entre un dispositivo origen y una IPv4 destino (`count` de 1 a 10), devolviendo tasa de éxito y RTT. |

---

## Requisitos e Instalación

* **Python**: 3.11 o superior.
* **Gestor de entorno**: [`uv`](https://docs.astral.sh/uv/).

```bash
# 1. Clonar el repositorio
git clone <URL_DEL_REPOSITORIO_EN_GITHUB>
cd packet-tracer-mcp

# 2. Copiar plantilla de variables de entorno
cp .env.example .env

# 3. Sincronizar entorno virtual y dependencias con uv
uv sync
```

---

## Ejecución del Entorno

### Paso 1: Iniciar el Agente Puente (`packet-tracer-agent`)
En una terminal dedicada, inicie el servidor TCP puente que escucha en `127.0.0.1:39000`:

```bash
uv run packet-tracer-agent
```

### Paso 2: Conectar el Servidor MCP (`packet-tracer-mcp`) a Claude Desktop u otro Cliente MCP
Agregue la siguiente entrada sanitizada en su archivo de configuración del cliente MCP (por ejemplo, `claude_desktop_config.json`), reemplazando `<RUTA_AL_PROYECTO>` por la ruta local hacia este repositorio:

```json
{
  "mcpServers": {
    "packet-tracer-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "<RUTA_AL_PROYECTO>",
        "run",
        "packet-tracer-mcp"
      ],
      "env": {
        "PT_HOST": "127.0.0.1",
        "PT_PORT": "39000",
        "PT_TIMEOUT_SECONDS": "10.0"
      }
    }
  }
}
```

---

## Ejecución de Pruebas Unitarias y de Seguridad

```bash
uv run pytest -v
```

---

## Seguridad y OPSEC

* **Anti-Inyección CLI**: `CliCommandRequest` rechaza cualquier intento de invocar binarios del sistema anfitrión (`bash`, `sh`, `rm`, `wget`, `curl`, `powershell`, `cmd`, `tclsh`, etc.), rutas de archivos o metacaracteres de encadenamiento lógico (`;`, `&&`, `||`, `` ` ``, `$()`, `>`, `<`).
* **Privacidad por Diseño**: El archivo `.gitignore` bloquea `.env`, certificados, logs, volcados de trazas y archivos de topología locales (`.pkt`, `.pkz`, `.pka`) para impedir fugas de metadatos en el control de versiones.
