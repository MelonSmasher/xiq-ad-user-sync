FROM python:3.12-alpine

# Default to 1 hour
ENV SYNC_INTERVAL_SEC=3600

WORKDIR /app

COPY . .

RUN python -m venv venv && \
    source venv/bin/activate && \
    python -m pip install -r requirements.txt

