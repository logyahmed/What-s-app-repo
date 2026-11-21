"""Side-effect-free helpers for MCP server configuration env vars."""

# Accepted WHATSAPP_MCP_TRANSPORT values mapped to FastMCP transport names.
# "http" is a friendly alias for the spec's current "streamable-http" transport.
TRANSPORT_ALIASES = {
    "stdio": "stdio",
    "http": "streamable-http",
    "streamable-http": "streamable-http",
    "streamable_http": "streamable-http",
    "sse": "sse",
}
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8000


def resolve_transport(value: str | None) -> str:
    """Map a WHATSAPP_MCP_TRANSPORT value to a FastMCP transport name.

    Unset or whitespace-only values default to "stdio".
    Raises ValueError for unrecognized values.
    """
    normalized = (value or "").strip().lower() or "stdio"
    try:
        return TRANSPORT_ALIASES[normalized]
    except KeyError:
        accepted = ", ".join(sorted(TRANSPORT_ALIASES))
        raise ValueError(
            f"Invalid WHATSAPP_MCP_TRANSPORT={value!r}; recommended values: stdio, http, sse "
            f"(http maps to the spec's streamable-http transport; all accepted inputs: {accepted})"
        ) from None


def resolve_host(value: str | None) -> str:
    """Parse WHATSAPP_MCP_HOST, defaulting to DEFAULT_MCP_HOST."""
    return (value or "").strip() or DEFAULT_MCP_HOST


def resolve_port(value: str | None) -> int:
    """Parse WHATSAPP_MCP_PORT, defaulting to DEFAULT_MCP_PORT.

    Unset or whitespace-only values default to DEFAULT_MCP_PORT.
    Raises ValueError for non-integer or out-of-range values.
    """
    value = (value or "").strip()
    if not value:
        return DEFAULT_MCP_PORT
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"Invalid WHATSAPP_MCP_PORT={value!r}; must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid WHATSAPP_MCP_PORT={value!r}; must be between 1 and 65535") from None
    return port


# --- Secure fork additions -------------------------------------------------

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}

TRUTHY = {"1", "true", "yes", "on"}


def env_flag(value: str | None) -> bool:
    """Interpret an env var as a boolean (1/true/yes/on, case-insensitive)."""
    return (value or "").strip().lower() in TRUTHY


def is_loopback_host(host: str) -> bool:
    """True when host only accepts connections from this machine."""
    h = (host or "").strip().lower()
    return h in LOOPBACK_HOSTS or h.startswith("127.")


def require_safe_host(host: str, allow_remote: str | None) -> str:
    """Refuse to expose the unauthenticated HTTP/SSE transport off-host.

    The network transports have no built-in authentication, so binding to
    0.0.0.0 or a LAN address would let anyone on the network read and send
    WhatsApp messages. That now requires an explicit
    WHATSAPP_MCP_ALLOW_REMOTE=true (meant for use behind an authenticating
    proxy or tunnel).
    """
    if is_loopback_host(host) or env_flag(allow_remote):
        return host
    raise ValueError(
        f"Refusing to bind WHATSAPP_MCP_HOST={host!r}: the HTTP/SSE transport has no "
        "authentication. Keep it on 127.0.0.1, or put it behind an authenticating proxy "
        "and set WHATSAPP_MCP_ALLOW_REMOTE=true."
    )
