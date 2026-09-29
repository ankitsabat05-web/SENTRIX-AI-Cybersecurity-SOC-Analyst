"""
=========================================================
SENTRIX - AI CYBERSECURITY SOC PLATFORM
FastAPI Application Entry Point
=========================================================

File:
    backend/app/main.py

Purpose:
    Main entry point for the SENTRIX backend.

Responsibilities:
    - Create FastAPI application
    - Configure CORS
    - Register API routes
    - Configure application metadata
    - Provide health/root endpoints
    - Handle startup/shutdown events
    - Handle unexpected API errors

Run:
    cd backend
    python -m uvicorn app.main:app --reload

API Documentation:
    http://127.0.0.1:8000/docs

Alternative Documentation:
    http://127.0.0.1:8000/redoc

=========================================================
"""

# =========================================================
# Standard Library Imports
# =========================================================

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict


# =========================================================
# FastAPI Imports
# =========================================================

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


# =========================================================
# Application Imports
# =========================================================

from app.api.routes import router


# =========================================================
# Application Configuration
# =========================================================

APP_NAME = "SENTRIX"

APP_VERSION = "1.0.0"

APP_DESCRIPTION = """
SENTRIX is an AI-powered Cybersecurity Security Operations
Center platform designed for security monitoring, threat
intelligence, AI-based threat detection, investigation,
correlation, and security reporting.
"""


# =========================================================
# Utility Function
# =========================================================

def utc_now() -> str:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(timezone.utc).isoformat()


# =========================================================
# Application Lifecycle
# =========================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    """
    Manage SENTRIX application startup and shutdown.

    Startup:
        - Initialize backend
        - Display system information

    Shutdown:
        - Gracefully stop backend services
    """

    # -----------------------------------------------------
    # STARTUP
    # -----------------------------------------------------

    print()
    print("=" * 60)
    print("SENTRIX - AI CYBERSECURITY SOC PLATFORM")
    print("=" * 60)
    print("[SYSTEM] Initializing SENTRIX backend...")
    print("[SYSTEM] FastAPI engine................ ONLINE")
    print("[SYSTEM] API router................... ONLINE")
    print("[SYSTEM] Threat Intelligence.......... READY")
    print("[SYSTEM] AI Detection Engine.......... READY")
    print("[SYSTEM] Investigation Engine......... READY")
    print("[SYSTEM] Reporting Engine............. READY")
    print("[SYSTEM] SENTRIX backend.............. ONLINE")
    print("=" * 60)
    print()

    yield

    # -----------------------------------------------------
    # SHUTDOWN
    # -----------------------------------------------------

    print()
    print("=" * 60)
    print("[SYSTEM] SENTRIX backend shutting down...")
    print("[SYSTEM] Services stopped.")
    print("[SYSTEM] SENTRIX offline.")
    print("=" * 60)
    print()


# =========================================================
# CREATE FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title=APP_NAME,

    description=APP_DESCRIPTION,

    version=APP_VERSION,

    docs_url="/docs",

    redoc_url="/redoc",

    openapi_url="/openapi.json",

    lifespan=lifespan
)


# =========================================================
# CORS CONFIGURATION
# =========================================================

"""
CORS allows the SENTRIX frontend to communicate with
the FastAPI backend.

During development, all origins are allowed.

For production, replace "*" with the actual frontend
domain.
"""

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# =========================================================
# REGISTER API ROUTER
# =========================================================

"""
All routes from app/routes.py are registered under:

    /api/v1

Examples:

    /api/v1/health
    /api/v1/dashboard
    /api/v1/threat-intelligence
    /api/v1/threat-intelligence/auto
    /api/v1/detect
    /api/v1/investigate
    /api/v1/reports
    /api/v1/system/status
"""

app.include_router(
    router,
    prefix="/api/v1"
)


# =========================================================
# ROOT ENDPOINT
# =========================================================

@app.get(
    "/",
    tags=["System"]
)
async def root() -> Dict[str, Any]:
    """
    SENTRIX root endpoint.

    Used to verify that the backend is running.
    """

    return {
        "success": True,

        "application": APP_NAME,

        "version": APP_VERSION,

        "status": "ONLINE",

        "message": "SENTRIX AI Cybersecurity SOC Platform is running.",

        "api_base": "/api/v1",

        "documentation": "/docs",

        "timestamp": utc_now()
    }


# =========================================================
# BACKEND HEALTH ENDPOINT
# =========================================================

@app.get(
    "/health",
    tags=["System"]
)
async def backend_health() -> Dict[str, Any]:
    """
    Basic backend health check.

    This endpoint is independent from /api/v1/health.
    """

    return {
        "success": True,

        "application": APP_NAME,

        "status": "healthy",

        "service": "FastAPI Backend",

        "version": APP_VERSION,

        "timestamp": utc_now()
    }


# =========================================================
# GLOBAL EXCEPTION HANDLER
# =========================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Catch unexpected backend errors.

    This prevents raw Python exceptions from being
    directly exposed to the frontend.
    """

    print()
    print("[ERROR] Unexpected server error")
    print(f"[ERROR] Method : {request.method}")
    print(f"[ERROR] Path   : {request.url.path}")
    print(f"[ERROR] Error  : {str(exc)}")
    print()

    return JSONResponse(
        status_code=500,

        content={
            "success": False,

            "error": {
                "code": "INTERNAL_SERVER_ERROR",

                "message": (
                    "An unexpected server error occurred."
                )
            },

            "timestamp": utc_now()
        }
    )


# =========================================================
# APPLICATION INFORMATION
# =========================================================

@app.get(
    "/system",
    tags=["System"]
)
async def system_information() -> Dict[str, Any]:
    """
    Return SENTRIX backend system information.
    """

    return {
        "success": True,

        "application": APP_NAME,

        "version": APP_VERSION,

        "platform": "AI Cybersecurity SOC",

        "status": "ONLINE",

        "components": {
            "fastapi": "ONLINE",
            "api_router": "ONLINE",
            "threat_intelligence": "READY",
            "ai_detection": "READY",
            "investigation": "READY",
            "reporting": "READY"
        },

        "api": {
            "base_url": "/api/v1",

            "documentation": "/docs",

            "openapi": "/openapi.json"
        },

        "timestamp": utc_now()
    }


# =========================================================
# DEVELOPMENT SERVER NOTE
# =========================================================

"""
Do NOT normally start Uvicorn directly from this file.

Recommended command:

    cd backend

    python -m uvicorn app.main:app --reload

For a different port:

    python -m uvicorn app.main:app --reload --port 8000

For network access:

    python -m uvicorn app.main:app --reload --host 0.0.0.0
"""
