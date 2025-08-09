# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Prevent Python from writing .pyc
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    useradd -ms /bin/bash appuser

COPY . .
RUN mkdir -p /app/proofs && chown -R appuser:appuser /app
USER appuser

# Render provides $PORT
ENV PORT=8000 \
    PROOFS_DIR=/app/proofs

CMD ["sh", "-c", "python -m uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
