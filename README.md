# ZeroShield

A Sandbox-Based Validation Framework for Zero-Click Vulnerability Mitigations — a defensive R&D prototype that converts selected VPN and Telecommunications zero-click CVE research into safe, reproducible, synthetic mitigation-validation experiments.

Status: **Milestones 1–19 complete** — the core validation engine (experiment models, safety policy, VPN/Telecom baseline and mitigation strategies, metrics, evidence generation, Overleaf export), a first-release command-line interface, a Streamlit demonstration dashboard, and a synchronous FastAPI REST interface. Docker, RabbitMQ, MinIO, Prometheus, and Grafana have not been started.

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

### 3. Start the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn zeroshield.api.app:app --reload
```

Leave this window open — the API keeps running as long as this command is running.

### 4. Open Swagger (the interactive API test page)

In your browser, go to:

```
http://localhost:8000/docs
```

This page lists every endpoint and lets you send real requests by clicking "Try it out" — you never need to write an HTTP request by hand.

### 5. List experiments

In Swagger, open **GET /experiments** → "Try it out" → "Execute". You'll see `ZC-VPN-EXP-001` and `ZC-TELECOM-EXP-001` (or any other experiment file dropped into the `experiments/` folder — nothing is hard-coded).

### 6. Validate an experiment

Open **POST /experiments/{experiment_id}/validate** → "Try it out" → set `experiment_id` to `ZC-VPN-EXP-001` → in the request body put:

```json
{"execution_context": "local_unit_test"}
```

→ "Execute". You'll see whether ZeroShield's safety policy currently allows it to run, and why if not.

### 7. Run a draft experiment using local_unit_test

Both bundled experiments are still in `draft` review status, so the strict `experiment_run` context will always correctly refuse them (this is the safety gate working as intended, not a bug). To actually execute one for a local demonstration, use **POST /experiments/{experiment_id}/runs** with:

```json
{"execution_context": "local_unit_test"}
```

This runs the real baseline and mitigation and writes real evidence to `results/`.

### 8. Inspect results/evidence

- **GET /experiments/{experiment_id}/results** — the baseline-vs-mitigation comparison from the most recent run.
- **GET /experiments/{experiment_id}/evidence** — factual evidence metadata (run IDs, dataset hash, integrity check) for the most recent run.

Both return `404` until an experiment has actually been run at least once.

### 9. Stop the server

Go back to the PowerShell window running uvicorn and press `Ctrl+C`.
