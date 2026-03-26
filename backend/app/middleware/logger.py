from time import perf_counter

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.utils.logger import log_event


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started_at = perf_counter()
        method = request.method
        path = request.url.path
        ip_address = _client_ip(request)

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((perf_counter() - started_at) * 1000, 2)
            log_event(
                "ERROR",
                f"{method} {path} failed with {type(exc).__name__}",
                method=method,
                path=path,
                status_code=500,
                response_time_ms=duration_ms,
                ip=ip_address,
                error=str(exc),
            )
            raise

        duration_ms = round((perf_counter() - started_at) * 1000, 2)
        status_code = response.status_code
        level = "ERROR" if status_code >= 500 else "WARN" if status_code >= 400 else "INFO"

        log_event(
            level,
            f"{method} {path} -> {status_code} in {duration_ms}ms",
            method=method,
            path=path,
            status_code=status_code,
            response_time_ms=duration_ms,
            ip=ip_address,
        )
        return response
