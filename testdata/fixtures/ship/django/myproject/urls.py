"""URL routes for the ship fixture — a `/` health endpoint so the generated
Dockerfile's HEALTHCHECK (which probes `/`) reports healthy at runtime."""

from django.http import JsonResponse
from django.urls import path


def health(_request):
    return JsonResponse({"service": "ship-fixture-django", "status": "ok"})


urlpatterns = [
    path("", health),
]
