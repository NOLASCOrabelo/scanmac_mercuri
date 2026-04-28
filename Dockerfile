FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nmap \
    arp-scan \
    avahi-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "scan_02.py"]
