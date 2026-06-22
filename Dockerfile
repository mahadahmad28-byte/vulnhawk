FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY vulnhawk/ vulnhawk/
COPY web/ web/

# Install with web extras (FastAPI + uvicorn)
RUN pip install --no-cache-dir -e ".[web]"

# Expose web dashboard port
EXPOSE 8080

# Default: run the web dashboard
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8080"]
