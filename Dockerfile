FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8600

CMD ["uvicorn", "app.api_server:app", "--host", "0.0.0.0", "--port", "8600"]
