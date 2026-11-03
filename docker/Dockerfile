FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libffi-dev \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 oblvn \
    && mkdir -p /home/oblvn/.oblvn/logs /home/oblvn/.oblvn/certs /home/oblvn/.oblvn/ots \
    && chown -R oblvn:oblvn /home/oblvn/.oblvn /app

USER oblvn

EXPOSE 8000

CMD ["python", "run.py", "--no-browser", "--port", "8000"]
