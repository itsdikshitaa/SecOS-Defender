FROM python:3.11-slim

WORKDIR /workspace/server

COPY server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY server ./server
COPY rules ./rules

ENV PYTHONPATH=/workspace/server/server

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
