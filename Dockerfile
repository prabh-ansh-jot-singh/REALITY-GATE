FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REALITY_GATE_HOST=0.0.0.0 \
    REALITY_GATE_PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY reality_gate/ ./reality_gate/
COPY frontend/ ./frontend/
COPY eval/ ./eval/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY main.py .
COPY logo.png .
COPY logo.jpg .
COPY .env.example .

RUN mkdir -p /app/logs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

CMD ["uvicorn", "reality_gate.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
