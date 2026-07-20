FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY controller/pyproject.toml controller/pyproject.toml
COPY controller/src controller/src
COPY analysis/pyproject.toml analysis/pyproject.toml
COPY analysis/src analysis/src
RUN pip install --no-cache-dir ./analysis ./controller
USER 65532:65532
EXPOSE 8000
CMD ["uvicorn", "c2hunter_controller.app:app", "--host", "0.0.0.0", "--port", "8000"]
