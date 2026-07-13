"""Minimal FastAPI app — a docker-buildable ship fixture (testdata/fixtures/ship).

The generated Dockerfile runs `uvicorn main:app` and its HEALTHCHECK probes
`/health`, so this module exposes `app` at module scope plus a `/health` route.
It reads no runtime secret at import time, so `docker build` never depends on
environment configuration.
"""

from fastapi import FastAPI

app = FastAPI(title="ship-fixture-fastapi")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "ship-fixture-fastapi"}
