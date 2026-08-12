FROM python:3.11-slim

LABEL maintainer="Krishnendu Paul <me@krishnendu.com>"
LABEL description="HostVigil - Stealth internal reconnaissance platform"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        libpcap-dev \
        tcpdump \
        net-tools \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create data directories
RUN mkdir -p data/logs data/models data/scans data/reports

# Expose dashboard port
EXPOSE 5000

# Run daemon mode (continuous recon + dashboard)
ENTRYPOINT ["python", "run.py"]
CMD ["daemon"]
