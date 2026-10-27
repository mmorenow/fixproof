# The vulnerable internal app. Built locally (there is no public image for a
# private app), the same way MLflow is built from source. A canary file is planted
# OUTSIDE the web root so a passing PoC proves a real traversal, not just a 200.
FROM python:3.12-slim

# Cosmetic: a build label so the image tag carries a version, like a real build.
ARG VULNAPP_VERSION=1.0.0
LABEL vulnapp.version=$VULNAPP_VERSION

WORKDIR /app
COPY server.py /app/server.py
RUN mkdir -p /app/public \
    && echo "<h1>internal app</h1>" > /app/public/index.html \
    && echo "CANARY-SECRET-7f3a" > /secret_canary.txt

EXPOSE 8080
CMD ["python", "/app/server.py"]
