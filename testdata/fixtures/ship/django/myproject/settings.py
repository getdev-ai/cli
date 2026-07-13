"""Minimal Django settings — a docker-buildable ship fixture.

Build-time-safe (07 Pitfall 2): every value has an inline default so importing
this module — which `gunicorn myproject.wsgi:application` does at container
start — never requires a runtime SECRET_KEY / DATABASE_URL to be present. A
production deployment overrides these via the environment, but `docker build`
(which only pip-installs and copies files, never imports settings) and a bare
`import myproject.settings` both succeed without any configuration.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Dev default only — a real deployment MUST override via the environment.
SECRET_KEY = os.environ.get("SECRET_KEY", "ship-fixture-insecure-dev-key")

DEBUG = os.environ.get("DEBUG", "0") == "1"

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "myproject.urls"

WSGI_APPLICATION = "myproject.wsgi.application"

# SQLite keeps the fixture dependency-free — no external DATABASE_URL at import.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
