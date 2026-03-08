from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db
from .routes.audit import router as audit_router
from .routes.security import router as security_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


def get_cors_origins() -> list[str]:
    env_value = os.environ.get("CLAWSHIELD_CORS_ORIGINS", "").strip()
    if env_value:
        return [origin.strip() for origin in env_value.split(",") if origin.strip()]
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]


def create_app() -> FastAPI:
    app = FastAPI(title="ClawShield", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/healthz")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(security_router)
    app.include_router(audit_router)
    return app


app = create_app()
