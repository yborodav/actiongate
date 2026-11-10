# ActionGate server image.
#   docker build -t actiongate .
#   docker run -p 8080:8080 -e ACTIONGATE_VAULT_KEY -v "$PWD/actiongate.yaml:/app/actiongate.yaml:ro" \
#     -v "$PWD/data:/app/data" actiongate
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY actiongate ./actiongate
RUN pip install . && useradd --create-home --uid 10001 actiongate && mkdir -p /app/data \
    && chown actiongate:actiongate /app/data

# Run as a non-root user; credentials, keys and the database live in the mounted /app/data.
USER actiongate
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
ENTRYPOINT ["python", "-m", "actiongate"]
CMD ["serve", "--config", "/app/actiongate.yaml", "--host", "0.0.0.0", "--port", "8080"]
