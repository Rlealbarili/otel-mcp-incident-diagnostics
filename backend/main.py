"""
Main Application Entrypoint for CIRES System Health Observability Backend.

Integrates FastAPI app, TelemetryMiddleware, health routes, system routes,
fault simulator endpoints, and serves the frontend observability dashboard.
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.middleware.telemetry import TelemetryMiddleware, StructuredJSONLogFormatter
from backend.routes.health_routes import router as health_router
from backend.routes.system_routes import router as system_router, patients_compat_router
from backend.workers.fault_simulator import router as fault_router
from backend.workers.health_ingestion import init_telemetry

# Configure structured JSON logging
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(StructuredJSONLogFormatter(service_name="health-observability-backend"))
logger.handlers = [handler]
logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager initializing OTel SDK telemetry on startup."""
    init_telemetry(service_name="health-observability-backend", protocol="grpc")
    yield


app = FastAPI(
    title="CIRES Software System Health & AI Incident Diagnostics API",
    description="Privacy-first, resilient software system telemetry ingestion and automated incident diagnostics backend under CIRES-R governance.",
    version="1.0.0",
    lifespan=lifespan,
)

# Attach Telemetry Middleware
app.add_middleware(TelemetryMiddleware)

# Mount APIRouters
app.include_router(health_router)
app.include_router(system_router)
app.include_router(patients_compat_router)
app.include_router(fault_router)

# Mount Frontend Static Directory
frontend_public_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "public")
if os.path.exists(frontend_public_dir):
    app.mount("/static", StaticFiles(directory=frontend_public_dir), name="static")


@app.get("/")
async def root(request: Request):
    """Root endpoint serving JSON status by default or HTML UI if requested."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        index_file = os.path.join(frontend_public_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)

    return JSONResponse(
        content={
            "service": "health-observability-backend",
            "status": "operational",
            "telemetry_pipeline": "OpenTelemetry + Grafana LGTM",
            "security_policy": "FAIL_CLOSED_SECRET_SANITATION",
            "ui_url": "/ui",
        }
    )


@app.get("/ui")
async def serve_ui():
    """Serves the Glassmorphic Observability Dashboard."""
    index_file = os.path.join(frontend_public_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse(status_code=404, content={"error": "UI dashboard file not found."})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000)

