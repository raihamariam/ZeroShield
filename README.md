# ZeroShield

A Sandbox-Based Validation Framework for Zero-Click Vulnerability Mitigations — a defensive R&D prototype that converts selected VPN and Telecommunications zero-click CVE research into safe, reproducible, synthetic mitigation-validation experiments.

Status: **Milestones 1–22 complete** — the core validation engine (experiment models, safety policy, VPN/Telecom baseline and mitigation strategies, metrics, evidence generation, Overleaf export), a first-release command-line interface, a Streamlit demonstration dashboard, a FastAPI REST interface, a Docker image/Compose setup, asynchronous experiment execution via RabbitMQ and a worker process, and an optional S3-compatible (MinIO) evidence storage backend alongside the default local one. Prometheus and Grafana have not been started.

Authoritative requirements source: `ZC_Mitigation_Validation_Framework_SRS.docx` (draft, pending supervisor approval).

## Running the ZeroShield Dashboard

ZeroShield includes a visual dashboard so you can run and inspect experiments without using the command line or reading any code. This section assumes you have never used a terminal before.

### 1. Open a terminal in the project folder

- Open **PowerShell** (search for it in the Start menu).
- Move into the ZeroShield project folder by typing (adjust the path if your copy is somewhere else):

  ```powershell
  cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
  ```

### 2. One-time setup (only needed the first time, or after an update)

Install the project and the dashboard's dependencies into its virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dashboard,dev]"
```

You only need to do this again if you pull new code changes.

### 3. Launch the dashboard

From the project folder, run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run src/zeroshield/dashboard/app.py
```

A browser tab should open automatically at `http://localhost:8501`. If it doesn't, open that address in your browser manually.

### 4. Using the dashboard

- The **sidebar** lets you pick which experiment to look at (e.g. `ZC-VPN-EXP-001` or `ZC-TELECOM-EXP-001`).
- The **Overview** tab explains what ZeroShield does.
- The **Experiment & Safety** tab shows the experiment's details and whether ZeroShield's safety check currently allows it to run. If it's denied, the reason is shown and the "Run Experiment" button is disabled — this cannot be bypassed from the dashboard.
- Click **Run Experiment** to execute it. This runs the same underlying engine used by the command line — nothing about the results is invented or adjusted for display.
- The **Results**, **Test Cases**, and **Evidence** tabs then show what happened, including a case-by-case before-vs-after comparison.
- The **Overleaf Export** tab produces a factual summary file for manual inclusion in the research write-up — it never edits the shared Overleaf document directly.

### 5. Closing the dashboard

Go back to the PowerShell window and press `Ctrl+C`.

## Running the ZeroShield API

ZeroShield also includes a REST API, so other programs (or you, using a browser-based test page) can list, validate, run, and inspect experiments over HTTP. This section assumes you have never used a terminal or an API before.

### 1. Open a terminal in the project folder

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
```

### 2. One-time setup (only needed the first time, or after an update)

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
```

### 3. Start RabbitMQ and the worker (required for runs to actually complete)

As of Milestone 21, submitting a run no longer executes it directly — the API queues it on RabbitMQ and a separate **worker** process picks it up. Without a running broker and worker, a submitted run will just sit as `queued` forever. The simplest way to get RabbitMQ running is via Docker, even if you're running the API itself natively:

```powershell
docker compose up -d rabbitmq
```

Then, in a second PowerShell window, start the worker:

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
.\.venv\Scripts\python.exe -m pip install -e ".[queue,dev]"
.\.venv\Scripts\python.exe -m zeroshield.worker
```

Leave this window open too — the worker keeps running and processing jobs as long as this command is running.

### 4. Start the API

In a third PowerShell window:

```powershell
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Leave this window open — the API keeps running as long as this command is running.

### 5. Open Swagger (the interactive API test page)

In your browser, go to:

```
http://localhost:8000/docs
```

This page lists every endpoint and lets you send real requests by clicking "Try it out" — you never need to write an HTTP request by hand.

### 6. List experiments

In Swagger, open **GET /experiments** → "Try it out" → "Execute". You'll see `ZC-VPN-EXP-001` and `ZC-TELECOM-EXP-001` (or any other experiment file dropped into the `experiments/` folder — nothing is hard-coded).

### 7. Validate an experiment

Open **POST /experiments/{experiment_id}/validate** → "Try it out" → set `experiment_id` to `ZC-VPN-EXP-001` → in the request body put:

```json
{"execution_context": "local_unit_test"}
```

→ "Execute". You'll see whether ZeroShield's safety policy currently allows it to run, and why if not.

### 8. Run a draft experiment using local_unit_test

Both bundled experiments are still in `draft` review status, so the strict `experiment_run` context will always correctly refuse them (this is the safety gate working as intended, not a bug). To actually execute one for a local demonstration, use **POST /experiments/{experiment_id}/runs** with:

```json
{"execution_context": "local_unit_test"}
```

→ "Execute". This queues the run and returns immediately with a `job_id` and `status: "queued"` — it does not run the experiment itself. The worker (started in step 3) picks the job up, runs it for real, and writes real evidence to `results/`.

Copy the `job_id`, then open **GET /jobs/{job_id}** → paste it in → "Execute". Keep re-running it (a few seconds apart) until `status` becomes `completed` (or `denied`/`failed`, with a reason) — that response also includes the key metrics and where the evidence was written.

### 9. Inspect results/evidence

Once a job has completed:

- **GET /experiments/{experiment_id}/results** — the baseline-vs-mitigation comparison from the most recent run.
- **GET /experiments/{experiment_id}/evidence** — factual evidence metadata (run IDs, dataset hash, integrity check) for the most recent run.

Both return `404` until an experiment has actually been run at least once.

### 10. Stop everything

Go back to each PowerShell window (uvicorn, the worker) and press `Ctrl+C`, then stop RabbitMQ:

```powershell
docker compose down
```

## Running ZeroShield with Docker

If you have Docker Desktop installed, you can run everything — API, dashboard, RabbitMQ, and the worker — without installing Python or any dependencies on your own machine at all. This is the easiest way to get asynchronous runs working, since it starts RabbitMQ and the worker for you automatically.

### 1. Install Docker Desktop

Download it from docker.com if you don't already have it, and make sure it's running (its whale icon appears in the system tray).

### 2. Build and start ZeroShield

```powershell
cd C:\Users\raiha\OneDrive\Desktop\ZeroShield
docker compose up --build
```

The first build downloads and installs everything and can take a few minutes; later runs are much faster. This starts four containers: `rabbitmq`, `api`, `worker`, and `dashboard` — a run submitted through the API here is picked up and executed automatically, with no extra steps.

### 3. Open the tools

- API Swagger: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501`
- RabbitMQ management UI (optional, for the curious): `http://localhost:15673` (login `guest`/`guest`)

They behave exactly like the non-Docker versions described above — same safety checks, same experiments, same real evidence generation.

### 4. Where results go

Anything ZeroShield generates while running in Docker (evidence, comparisons, Overleaf exports, job records) is written to the same `results/`, `overleaf_exports/`, and `jobs/` folders you'd see running it directly — Docker doesn't hide or lose this data, it's shared with your project folder automatically.

### 5. Stop everything

```powershell
docker compose down
```

### Using the command-line tool via Docker

One-off CLI commands can be run against the same image without starting the API/dashboard, for example:

```powershell
docker run --rm zeroshield:latest zeroshield --help
```

## Optional: MinIO evidence storage

By default, ZeroShield stores evidence (manifests, results, comparisons) as plain files under `results/`. As of Milestone 22, an S3-compatible alternative (`MinioEvidenceRepository`, in `zeroshield.repositories`) is also available, backed by [MinIO](https://min.io) — proving the evidence-storage design can be swapped without touching any research/orchestration code. It is **not** the default: the CLI, dashboard, API, and worker all still use local file storage unless you write your own script that constructs a `MinioEvidenceRepository` and passes it to `zeroshield.orchestration.execute_and_generate_evidence` yourself.

To try it:

```powershell
docker compose up -d minio
.\.venv\Scripts\python.exe -m pip install -e ".[storage,dev]"
```

Then, in Python, use `zeroshield.repositories.minio_evidence_repository.default_minio_client()` (reads `MINIO_ENDPOINT`/`MINIO_ACCESS_KEY`/`MINIO_SECRET_KEY`/`MINIO_SECURE`, defaulting to `localhost:9002` with the credentials set in `docker-compose.yml`) together with `MinioEvidenceRepository(client, bucket_name)` in place of `LocalEvidenceRepository`. The MinIO web console is at `http://localhost:9003` (login `zeroshield`/`zeroshield123`) if you want to browse stored evidence visually.
