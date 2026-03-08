from __future__ import annotations

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


def create_app() -> FastAPI:
    app = FastAPI(title="ClawShield", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
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
