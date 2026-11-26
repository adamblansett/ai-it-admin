import asyncio
import json
import time
from collections import defaultdict, deque

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings

_EXEMPT_SUFFIXES = (
    "/health",
    "/health/live",
    "/health/ready",
    "/metrics",
)


class RateLimitMiddleware:
    """Pure ASGI sliding-window rate limiter keyed by client IP and actor email."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self.window_seconds = 60.0
        self._lock = asyncio.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def _is_exempt(self, path: str) -> bool:
        clean = path.rstrip("/")
        return any(clean.endswith(suffix) for suffix in _EXEMPT_SUFFIXES)

    def _bucket_key(self, scope: Scope) -> str:
        forwarded_for = ""
        actor_email = ""
        for key, value in scope.get("headers") or []:
            lower = key.decode("latin-1").lower()
            if lower == "x-forwarded-for":
                forwarded_for = value.decode("latin-1", errors="ignore").split(",")[0].strip()
            elif lower == "x-actor-email":
                actor_email = value.decode("latin-1", errors="ignore").strip().lower()

        client = scope.get("client")
        client_ip = forwarded_for or (str(client[0]) if client else "unknown")
        return f"{client_ip}:{actor_email or 'anon'}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.settings.rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        if self._is_exempt(path):
            await self.app(scope, receive, send)
            return

        limit = max(1, int(self.settings.rate_limit_requests_per_minute))
        key = self._bucket_key(scope)
        now = time.monotonic()
        cutoff = now - self.window_seconds

        async with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                retry_after = max(1, int(self.window_seconds - (now - bucket[0])) + 1)
                reset_epoch = int(time.time()) + retry_after
                payload = json.dumps(
                    {
                        "detail": "Rate limit exceeded. Retry shortly.",
                        "limit_per_minute": limit,
                        "retry_after_seconds": retry_after,
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(payload)).encode("ascii")),
                            (b"x-ratelimit-limit", str(limit).encode("ascii")),
                            (b"x-ratelimit-remaining", b"0"),
                            (b"x-ratelimit-reset", str(reset_epoch).encode("ascii")),
                            (b"retry-after", str(retry_after).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": payload})
                return

            bucket.append(now)
            remaining = max(0, limit - len(bucket))
            oldest = bucket[0] if bucket else now
            reset_epoch = int(time.time() + max(1.0, self.window_seconds - (now - oldest)))

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.extend(
                    [
                        (b"x-ratelimit-limit", str(limit).encode("ascii")),
                        (b"x-ratelimit-remaining", str(remaining).encode("ascii")),
                        (b"x-ratelimit-reset", str(reset_epoch).encode("ascii")),
                    ]
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
