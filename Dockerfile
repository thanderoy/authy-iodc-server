FROM python:3.13-slim-bookworm AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

# Install dependencies first for better caching
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

# Copy project source
COPY . /app

# Install project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Final stage
FROM python:3.13-slim-bookworm

# Setup non-root user
RUN addgroup --system appgroup && adduser --system --group appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/app/.venv/bin:$PATH"
ENV DJANGO_SETTINGS_MODULE="config.settings"
ENV PYTHONPATH="/app/src"

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appgroup /app /app

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:8000", "config.wsgi:application"]
