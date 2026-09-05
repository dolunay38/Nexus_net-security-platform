FROM python:3.12-slim
WORKDIR /app
# git nur fuer optionale Code-Updates (Policy-gesteuert, standardmaessig aus)
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8800
# Wissensbasis liegt persistent unter /data (Volume)
VOLUME ["/data"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8800"]
