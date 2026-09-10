FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN mkdir -p /app/data /app/uploads

ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data
ENV UPLOAD_DIR=/app/uploads
ENV DB_PATH=/app/data/chat.db

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
