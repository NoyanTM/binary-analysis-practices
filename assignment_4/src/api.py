from fastapi import FastAPI

from src.routes import ghidra_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router=ghidra_router)
    return app
    