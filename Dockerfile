# Einfaches Dockerfile zum lokalen Betrieb (MVP)
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# App-Dateien kopieren
COPY . /app

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "app.py"]