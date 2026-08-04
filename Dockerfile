# ZeroShield container image (Milestone 20).
#
# Packages the existing API/dashboard/CLI for isolated, reproducible execution
# (SRS 14: "Docker/Compose - Isolation and reproducibility ... not a substitute
# for experiment validity"). No safety, strategy, or metric logic lives here -
# this only packages the already-implemented Core/CLI/dashboard/API unchanged.
#
# One image serves both the API and the dashboard (different `command:` per
# service in docker-compose.yml) so dependency layers aren't built twice.
# results/ and overleaf_exports/ are NOT baked in - they are generated output
# and are mounted as volumes in docker-compose.yml so evidence persists on
# the host, consistent with how the rest of the project treats them
# (.gitignore excludes their contents for the same reason).

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY experiments ./experiments
COPY test_data ./test_data

RUN pip install --no-cache-dir ".[api,dashboard]"

RUN mkdir -p results overleaf_exports

EXPOSE 8000 8501

CMD ["python", "-m", "uvicorn", "zeroshield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
