FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py db.py auth.py ./

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python3 -c "import socket; socket.create_connection(('localhost', 8000), 2).close()"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
