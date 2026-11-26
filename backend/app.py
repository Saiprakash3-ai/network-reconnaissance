from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.api.routes import router
from config.loader import load_settings
from database.session import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(
        title=settings.get("app", {}).get("name", "Network Reconnaissance"),
        version="0.1.0",
        description="Local-first Advanced Network Reconnaissance & Intelligence Laboratory",
        lifespan=lifespan,
    )
    app.include_router(router, prefix="/api")
    return app


app = create_app()
