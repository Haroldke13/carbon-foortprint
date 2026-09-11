# syntax=docker/dockerfile:1
###############################################################################
# carbon-foortprint — Flask + SQLAlchemy carbon-footprint calculator with
# Stripe / PayPal offset payments
#
# Build:  docker build -t carbon:latest .
# Run:    see DEPLOY.md
#
# *** DO NOT EXPOSE THIS PUBLICLY YET. ***
# config.py, app/__init__.py, app/extensions.py and app/paypal_client.py each
# contain hardcoded live-prefixed Stripe keys and PayPal client secrets, in a
# public repository. Rotate them at the provider first. DEPLOY.md section 1.
###############################################################################

FROM python:3.12.3-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# requirements-deploy.txt, not requirements.txt — see the header of that file.
COPY requirements-deploy.txt ./
RUN python -m pip install --upgrade pip setuptools wheel \
 && python -m pip install -r requirements-deploy.txt

FROM python:3.12.3-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=5761

COPY --from=builder /opt/venv /opt/venv

RUN useradd --system --create-home --uid 10005 --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --chown=root:root . /app

# create_app() calls db.create_all() at import time. With the default
# sqlite:///site.db, Flask-SQLAlchemy 3.x resolves that relative path inside the
# instance folder, so /app/instance must exist and be writable or the app cannot
# start. Mount a volume here, or set DATABASE_URL to a real Postgres and this
# directory stays empty.
RUN mkdir -p /app/instance && chown appuser:appuser /app/instance
VOLUME ["/app/instance"]

USER appuser

EXPOSE 5761

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5761/healthz', timeout=4).status == 200 else 1)"

# Keep it at 2 workers while the database is SQLite: more writers means
# 'database is locked'. Raise it after moving to Postgres.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5761", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "60", \
     "--graceful-timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "deploy_wsgi:app"]
