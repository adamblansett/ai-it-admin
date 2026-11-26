import ipaddress
from urllib.parse import urlparse

from fastapi import HTTPException, status

_BLOCKED_EXACT_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "0.0.0.0",
    }
)
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")


def _is_forbidden_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_webhook_url(url: str, *, app_env: str = "development") -> str:
    """Validate an outbound webhook URL against SSRF and scheme policies."""
    cleaned = url.strip()
    parsed = urlparse(cleaned)

    allowed_schemes = ("https",) if app_env.strip().lower() == "production" else ("http", "https")
    if parsed.scheme.lower() not in allowed_schemes:
        expected = "https" if app_env.strip().lower() == "production" else "http/https"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook URL scheme must be {expected}.",
        )

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook URL must contain a valid hostname.",
        )

    if host in _BLOCKED_EXACT_HOSTS or any(host.endswith(sfx) for sfx in _BLOCKED_SUFFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook host '{host}' is blocked by SSRF protection.",
        )

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None and _is_forbidden_ip(ip_obj):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook IP '{host}' is in a restricted private/loopback/link-local range.",
        )

    return cleaned
