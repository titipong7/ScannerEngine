# syntax=docker/dockerfile:1

###############################################################################
# Scanner Engine — ARM64 image for Oracle Cloud Ampere A1 (also builds on amd64)
#
#   docker build --platform linux/arm64 -t scanner-engine:latest .
###############################################################################

############################
# Stage 1 — build the venv #
############################
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential is needed on arm64 for any wheel that is not published for
# aarch64 (cryptography, etc.) and is thrown away with this stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

############################
# Stage 2 — runtime        #
############################
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# curl is only used by the container healthcheck below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=scanner:scanner main.py ./
COPY --chown=scanner:scanner app ./app

USER scanner
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Ampere A1 cores are plentiful; 2 workers is a sane default for the free tier.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
