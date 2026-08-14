FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY analysis/pyproject.toml analysis/pyproject.toml
COPY analysis/src analysis/src
COPY sensor/worker/src worker
RUN chmod -R a+rX /app/worker
RUN pip install --no-cache-dir ./analysis redis==5.2.1 "psycopg[binary]==3.2.9"
ENV PYTHONPATH=/app/worker
USER 65532:65532
ENTRYPOINT ["python", "-m", "c2hunter_worker"]
CMD ["run"]
