"""WSGI entrypoint — the generated Dockerfile serves this with
`gunicorn myproject.wsgi:application`, so `application` must exist at module
scope. Importing it does not require any runtime secret (see settings.py)."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

application = get_wsgi_application()
