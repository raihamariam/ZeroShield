# ZeroShield container image (Milestones 20-21).
#
# Packages the existing API/dashboard/CLI/worker for isolated, reproducible
# execution (SRS 14: "Docker/Compose - Isolation and reproducibility ... not
# a substitute for experiment validity"). No safety, strategy, or metric
# logic lives here - this only packages the already-implemented Core/CLI/
# dashboard/API/worker unchanged.
#
# One image serves the API, the dashboard, and the RabbitMQ worker (different
# `command:` per service in docker-compose.yml) so dependency layers aren't
# built three times. results/, overleaf_exports/, and jobs/ are NOT baked in
# - they are generated output and are mounted as volumes in
# docker-compose.yml so evidence and job records persist on the host,
# consistent with how the rest of the project treats them (.gitignore
# excludes their contents for the same reason).

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY experiments ./experiments
COPY test_data ./test_data

RUN pip install --no-cache-dir ".[api,dashboard,queue]"

RUN mkdir -p results overleaf_exports jobs

EXPOSE 8000 8501

CMD ["python", "-m", "uvicorn", "zeroshield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
