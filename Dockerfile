FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY config.example.yaml ./config.yaml

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["-c", "config.yaml"]
