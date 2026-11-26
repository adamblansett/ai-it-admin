import time
import uuid

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.metrics import MetricsRegistry


class SecurityHeadersMiddleware:
    """Pure ASGI middleware injecting X-Request-ID, timing, metrics, and security headers."""

    def __init__(
        self,
        app: ASGIApp,
        settings: Settings,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self.app = app
        self.settings = settings
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id: str | None = None
        for key, value in scope.get("headers") or []:
            if key.decode("latin-1").lower() == "x-request-id":
                candidate = value.decode("latin-1", errors="ignore").strip()[:128]
                if candidate:
                    request_id = candidate
                    break
        resolved_id = request_id or str(uuid.uuid4())
        started = time.perf_counter()
        method = str(scope.get("method", "GET"))
        path = str(scope.get("path", "/"))

        structlog.contextvars.bind_contextvars(request_id=resolved_id)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                duration_ms = (time.perf_counter() - started) * 1000.0
                status_code = int(message.get("status", 200))
                if self.metrics is not None:
                    self.metrics.record_http_request(
                        method=method,
                        path=path,
                        status_code=status_code,
                        duration_ms=duration_ms,
                    )

                headers = list(message.get("headers") or [])
                existing = {k.lower() for k, _ in headers}

                def _set_header(name: bytes, val: bytes) -> None:
                    if name.lower() not in existing:
                        headers.append((name, val))
                        existing.add(name.lower())

                _set_header(b"x-request-id", resolved_id.encode("latin-1"))
                _set_header(b"x-process-time-ms", f"{duration_ms:.2f}".encode("ascii"))
                _set_header(b"x-content-type-options", b"nosniff")
                _set_header(b"x-frame-options", b"DENY")
                _set_header(b"referrer-policy", b"strict-origin-when-cross-origin")
                _set_header(
                    b"permissions-policy",
                    b"camera=(), microphone=(), geolocation=()",
                )
                if self.settings.app_env.strip().lower() == "production":
                    _set_header(
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains",
                    )
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
