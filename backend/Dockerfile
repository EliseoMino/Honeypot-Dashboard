# Ingestion API image.
#
# The build context is the repository root, so the same pattern applies to the
# three application images. The TLS material is never baked in: it is mounted
# read only at runtime from var/certs, which the cert-init service generates.

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# The project metadata is copied before the sources so that editing the
# application does not invalidate the dependency layer.
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/src ./src
RUN pip install --no-cache-dir .

COPY backend/scripts/healthcheck.py /app/scripts/healthcheck.py

# The unprivileged account the API runs as. The spool and the certificates are
# bind mounted with the ownership the compose file sets up, so nothing inside
# the image needs to be writable.
RUN useradd --create-home --uid 10001 honeypot

# The spool is a named volume. Docker seeds a fresh empty volume with the
# contents and ownership of the image directory it covers, so creating it here
# owned by the runtime user is what lets the API write into it as non-root.
RUN mkdir -p /var/lib/honeypot/spool && chown -R honeypot:honeypot /var/lib/honeypot

USER honeypot

EXPOSE 8443

# Probes /healthz over mutual TLS with the dedicated probe certificate, so the
# container never needs the agent or nginx private key.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "/app/scripts/healthcheck.py"]

CMD ["honeypot-backend"]
