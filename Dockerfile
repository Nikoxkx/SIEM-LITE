FROM python:3.12-slim

LABEL maintainer="SIEM-Lite Project"
LABEL description="SIEM-Lite Log Correlation Engine"

# Create non-root user
RUN groupadd -r siem && useradd -r -g siem -m -d /home/siem siem

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=siem:siem . .

# Create data directory
RUN mkdir -p /app/data && chown siem:siem /app/data

# Switch to non-root user
USER siem

# Expose the web port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/api/health')" || exit 1

# Run the application
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8443"]
