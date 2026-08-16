"""Cyber Surakshya API — application assembly.

This file wires the application together and does nothing else. Endpoint
handlers live in `api/routers/`, read-model projections in `api/projections.py`,
platform construction in `api/runtime.py`, and authentication in
`api/security.py`.

It was previously a single 1,646-line module holding dependency wiring,
authentication, 45 endpoints across eight domains, an SSE generator, six
hardcoded attack profiles and several private helpers. Everything shared state
through a dozen module-level globals rebound inside one function, so no other
module could import a piece of it without importing all of it.

ROUTE OWNERSHIP
---------------
    /health, /feed, /feed/recent   public          api/routers/health.py
    /predict*                      authenticated   api/routers/prediction.py
    /alerts*, /analyses*           authenticated   api/routers/alerts.py
    /agents*, /stats, /debug/*     authenticated   api/routers/status.py
    /response/*, /blocked-ips*     authenticated   api/routers/response.py
    /ingestion/*                   authenticated   api/routers/ingestion.py
    /learning/*                    authenticated   api/routers/learning.py
    /simulation/*                  authenticated   api/routers/simulation.py
"""
# Load .env before anything reads os.environ. api.security raises at import
# when CYBER_SURAKSHYA_API_KEY is unset, and Redis disables its anonymous
# `default` user, so the ingestion layer needs credentials the moment
# ensure_runtime() runs — relying on the operator having exported them in
# whichever terminal launched the server is how you get "Redis is unreachable:
# Authentication required" with Redis sitting there perfectly healthy.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is a declared dependency
    pass

import os
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routers import (
    alerts,
    health,
    ingestion,
    learning,
    prediction,
    response,
    simulation,
    status,
)
from api.runtime import ensure_runtime, shutdown
from api.security import AUTHENTICATED
from observability import attach_to_loggers

# Capture agent log records into the ring buffer that backs /feed. Done before
# ensure_runtime() so startup events appear in the feed too.
attach_to_loggers()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the platform on startup, release it on shutdown.

    Replaces `@app.on_event("startup")`, which is deprecated, and adds the
    shutdown half that never existed: the Qdrant client was left open, so
    `QdrantClient.__del__` raised `ImportError: sys.meta_path is None` during
    interpreter teardown, and a running packet capture outlived the server.
    """
    ensure_runtime()
    try:
        yield
    finally:
        shutdown()


app = FastAPI(title="Cyber Surakshya API", lifespan=lifespan)

# Locked to the local frontend dev servers. Widen deliberately, never to "*"
# with allow_credentials=True — that combination is rejected by browsers and
# signals the origin list was never thought about.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public: liveness and the activity feed. A health check behind an API key is
# a health check a load balancer cannot use.
app.include_router(health.router)

# Everything else requires X-API-Key.
api_router = APIRouter(dependencies=AUTHENTICATED)
for module in (prediction, alerts, status, response, ingestion, learning, simulation):
    api_router.include_router(module.router)
app.include_router(api_router)

# Serve the built frontend when present. Mounted LAST: a mount at "/" swallows
# every path that no earlier route matched, so registering it before the
# routers would shadow the entire API.
_FRONTEND_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "dist")
_FRONTEND_DIR = _FRONTEND_DIST if os.path.isdir(_FRONTEND_DIST) else "frontend"
if os.path.isdir(_FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
