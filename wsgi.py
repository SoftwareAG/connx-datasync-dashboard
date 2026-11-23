"""Production WSGI entry point: gunicorn wsgi:app"""

from connx_rest_app import app


__all__ = ["app"]
