FROM python:3.10-slim
ARG MLFLOW_VERSION
RUN pip install --no-cache-dir "mlflow==${MLFLOW_VERSION}"
EXPOSE 5000
CMD ["mlflow", "server", "--host", "0.0.0.0", "--port", "5000"]
