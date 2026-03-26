import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.utils.logger import get_log_history, log_event, subscribe, unsubscribe

router = APIRouter(prefix="/api/logs")


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@router.get("/history")
async def history():
    return get_log_history()


@router.get("/stream")
async def stream_logs(request: Request):
    queue = subscribe()
    client_ip = _client_ip(request)
    log_event("INFO", "Live log stream connected", event="sse_connect", ip=client_ip)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(entry)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            unsubscribe(queue)
            log_event("DEBUG", "Live log stream disconnected", event="sse_disconnect", ip=client_ip)

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
    }
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)
