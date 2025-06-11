FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    tcpdump \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy psutil

#maybe change to volume mount? look into
COPY anomaly.py /app/
WORKDIR /app

CMD ["python", "anomaly.py"]