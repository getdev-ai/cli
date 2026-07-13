"""Minimal Flask app — a docker-buildable ship fixture (testdata/fixtures/ship).

The generated Dockerfile serves this with `gunicorn app:app` and its HEALTHCHECK
probes `/`, so this module exposes the WSGI callable `app` at module scope with a
`/` route. It reads no runtime secret at import time, so `docker build` never
depends on environment configuration.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def root():
    return jsonify(service="ship-fixture-flask", status="ok")


@app.get("/health")
def health():
    return jsonify(status="ok")
