from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.analyze import router as analyze_router
from app.api.routes.logs import router as logs_router
from app.core.config import get_cors_origin_regex, get_cors_origins, settings
from app.middleware import RequestLoggerMiddleware
from app.utils.logger import log_event

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="AI Gateway + Scanner + Log Analyzer + Risk Engine",
    version=settings.app_version
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_origin_regex=get_cors_origin_regex(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggerMiddleware)

app.include_router(analyze_router, tags=["Analysis"])
app.include_router(logs_router, tags=["Logs"])


@app.get("/")
async def root():
    return {
        "name": "AI Secure Data Intelligence Platform",
        "version": settings.app_version,
        "model": settings.claude_model,
        "endpoints": ["/analyze", "/health", "/patterns", "/api/logs/history", "/api/logs/stream", "/docs"]
    }


@app.on_event("startup")
async def startup_event():
    log_event("INFO", "Backend application started", service="secureai-backend")
