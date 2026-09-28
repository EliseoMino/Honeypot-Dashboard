# Ingestion agent image.
#
# The agent is deliberately a separate image from the backend: it is the
# component that would run on the honeypot host, so keeping it independent means
# the honeypot never carries the backend code or its database access.

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY agent/pyproject.toml ./pyproject.toml
COPY agent/src ./src
RUN pip install --no-cache-dir .

# The agent only needs read access to the Cowrie log and to its own checkpoint,
# and it is the only holder of the agent private key.
RUN useradd --create-home --uid 10002 honeypot

# The checkpoint is a named volume, and Docker seeds a fresh empty volume with
# the contents and ownership of the image directory it covers. Creating it here
# owned by the runtime user is what lets the agent persist its read position as
# non-root.
RUN mkdir -p /var/lib/honeypot-agent && chown -R honeypot:honeypot /var/lib/honeypot-agent

USER honeypot

CMD ["honeypot-agent"]
