"""Tests for the secure-fork hardening (read-only mode, host guard, instructions)."""

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

import main
from mcp_config import env_flag, is_loopback_host, require_safe_host


class TestRequireSafeHost:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.5"])
    def test_loopback_allowed(self, host):
        assert require_safe_host(host, None) == host

    @pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", "::"])
    def test_remote_refused_by_default(self, host):
        with pytest.raises(ValueError, match="Refusing to bind"):
            require_safe_host(host, None)

    def test_remote_allowed_with_explicit_opt_in(self):
        assert require_safe_host("0.0.0.0", "true") == "0.0.0.0"

    def test_loopback_detection(self):
        assert is_loopback_host("LOCALHOST")
        assert not is_loopback_host("10.0.0.1")


@pytest.mark.parametrize(
    ("value", "expected"), [("1", True), ("YES", True), ("on", True), ("", False), (None, False), ("nope", False)]
)
def test_env_flag(value, expected):
    assert env_flag(value) is expected


def _tool_names(server: FastMCP) -> set[str]:
    return {t.name for t in asyncio.run(server.list_tools())}


class TestReadOnlyMode:
    def _server(self) -> FastMCP:
        server = FastMCP("t")
        for name in (*main.OUTBOUND_TOOLS, "list_messages"):
            server.add_tool(lambda: None, name=name)
        return server

    def test_read_only_removes_outbound_tools(self):
        server = self._server()
        removed = main.apply_read_only_mode(server, True)
        assert set(removed) == set(main.OUTBOUND_TOOLS)
        assert _tool_names(server) == {"list_messages"}

    def test_read_write_keeps_tools(self):
        server = self._server()
        assert main.apply_read_only_mode(server, False) == []
        assert set(main.OUTBOUND_TOOLS) <= _tool_names(server)


def test_server_ships_prompt_injection_instructions():
    assert "UNTRUSTED" in (main.mcp.instructions or "")


@pytest.mark.parametrize("tool", ["send_message", "send_file", "send_audio_message", "send_reaction"])
def test_send_tools_carry_security_note(tool):
    desc = {t.name: t.description for t in asyncio.run(main.mcp.list_tools())}[tool]
    assert desc.startswith("SECURITY:")
