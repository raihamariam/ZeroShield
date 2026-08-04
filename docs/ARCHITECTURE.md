# ZeroShield Architecture

This document is the architecture companion to [`docs/HANDOVER.md`](HANDOVER.md): where that document explains *what to run and how*, this one explains *how the system is put together*, grounded in the actual current `src/zeroshield` code (every box below names the real module it corresponds to) and cross-referenced against the SRS's own architecture figures (`ZC_Mitigation_Validation_Framework_SRS.docx`, §4 "System Context and Architecture").

## 1. Seven-layer logical architecture

The SRS's Figure 1 defines seven logical layers plus cross-cutting controls. The table below is that same structure, with each layer mapped to where it actually lives in this codebase today:

```mermaid
flowchart TB
    L1["1. Threat Intelligence<br/><i>NVD / CVE / vendor / CISA / EPSS evidence and prioritisation</i>"]
    L2["2. Knowledge &amp; Research<br/><i>CVE profiles, root causes, vendor fixes, mitigation gaps</i><br/>zeroshield.models.cve_reference"]
    L3["3. Experiment Definition<br/><i>Schemas, registry, test sets, hypotheses, acceptance criteria</i><br/>zeroshield.models.experiment_definition, zeroshield.experiments, zeroshield.strategies.registry"]
    L4["4. Experiment Execution<br/><i>Runner, worker, baseline/mitigated strategies</i><br/>zeroshield.runners, zeroshield.worker, zeroshield.strategies.*"]
    L5["5. Mitigation Validation<br/><i>Validation, normalisation, state checking, logging</i><br/>zeroshield.strategies.vpn/telecom strict_mitigation"]
    L6["6. Evidence &amp; Benchmark<br/><i>Run manifests, metrics, comparison reports, audit trail</i><br/>zeroshield.repositories, zeroshield.metrics"]
    L7["7. Governance &amp; Review<br/><i>Approval gates, safety policy, risk decisions, sign-off</i><br/>zeroshield.policies"]

    L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7

    CC["Cross-cutting: traceability (ZC-&lt;DOMAIN&gt;-EXP-&lt;NNN&gt; IDs, git_commit in every manifest) &middot; configuration management (Git, pyproject.toml extras) &middot; security (zeroshield.policies + tests/security/) &middot; observability (zeroshield.observability, Prometheus/Grafana) &middot; ethics (SAFE-00x rules, synthetic-only data)"]
    L1 -.-> CC
    L7 -.-> CC
```

A run does not literally pass through 7 sequential function calls — layers 1–2 are research inputs captured as data (a `CVEReference` embedded in an `ExperimentDefinition`), not runtime code paths. Layers 3–7 *are* real runtime stages, in the order shown, for every run regardless of which interface (CLI/dashboard/API/worker) triggered it: define → execute (with layer 7's safety gate evaluated *before* layer 4 does anything, see §3 below) → validate-as-you-process → record evidence → available for review.

## 2. Design patterns (SRS §4.2)

| Pattern | SRS's stated use | Where it actually is |
|---|---|---|
| Strategy | Baseline and mitigation algorithms implement a common interface | `zeroshield.strategies.base.ProcessingStrategy` — one abstract method, `process()`; implemented by `WeakSchemaLengthBaseline`/`StrictSchemaCanonicalisationMitigation` (VPN) and `WeakMandatoryFieldStateBaseline`/`StrictGrammarStateMachineMitigation` (Telecom). |
| Factory | Resolves strategy identifiers from approved identifiers | `zeroshield.strategies.registry.resolve_strategy` — a fixed dict lookup (`_REGISTRY`), not dynamic import, so an unknown/attacker-controlled `strategy_id` can never load arbitrary code. |
| Repository | Abstracts experiment, run and evidence persistence | `zeroshield.repositories.evidence_repository.EvidenceRepository` (ABC) — `LocalEvidenceRepository` (default, files under `results/`) and `MinioEvidenceRepository` (optional, S3-compatible). Orchestration code depends only on the ABC. |
| Producer–Consumer | API submits jobs; workers execute experiments | `zeroshield.api.routes.experiments.submit_run` publishes a `RunJobMessage` to RabbitMQ; `zeroshield.worker.main` consumes and calls `zeroshield.worker.processor.process_run_job`. |
| Dependency Injection | Runner receives repositories, clock, logger and strategies | `ExperimentRunner.run(...)` and `execute_and_generate_evidence(...)` take `evidence_repository`, `clock`, `baseline`/`mitigation` as parameters — nothing is a hidden global. |
| Policy Object | Safety and approval rules are evaluated before execution | `zeroshield.policies.safety_policy.SafetyPolicy` — evaluates `zeroshield.policies.rules.check_safe_00{1,2,3,4}_*` and returns a `PolicyDecision`; `ExperimentRunner.run()` raises `PolicyRefusalError` before touching the dataset if `decision.allowed` is `False`. |

One additional pattern not named in the SRS but used consistently across every interface: a **thin-interface-layer** — `zeroshield.cli.commands`, `zeroshield.dashboard.app`, `zeroshield.api.routes.*`, and `zeroshield.worker.processor` each only load input, call into `zeroshield.services.experiment_service` / `zeroshield.orchestration`, and format output. None of them re-implement validation, safety, or metrics logic — see §4 below.

## 3. Component view: how a call reaches the engine

Every interface is a thin wrapper over the same three-layer core. Nothing below "Services" differs based on which interface is calling it:

```mermaid
flowchart TB
    subgraph Interfaces["Thin interface layer (no business logic)"]
        CLI["zeroshield.cli.commands"]
        DASH["zeroshield.dashboard.app"]
        API["zeroshield.api.routes.*"]
        WORKER["zeroshield.worker.processor"]
    end

    subgraph Services["zeroshield.services.experiment_service"]
        SVC["run_experiment / check_safety / list_experiments / load_latest_evidence"]
    end

    subgraph Orchestration["zeroshield.orchestration"]
        ORCH["execute_and_generate_evidence"]
    end

    subgraph Core["Domain core"]
        RUNNER["zeroshield.runners.ExperimentRunner"]
        POLICY["zeroshield.policies.SafetyPolicy"]
        STRAT["zeroshield.strategies.registry"]
        METRICS["zeroshield.metrics"]
        REPO["zeroshield.repositories.EvidenceRepository"]
        MODELS["zeroshield.models (Pydantic, frozen)"]
    end

    CLI --> SVC
    DASH --> SVC
    API --> SVC
    WORKER --> SVC
    SVC --> ORCH
    ORCH --> RUNNER
    RUNNER --> POLICY
    RUNNER --> STRAT
    ORCH --> METRICS
    ORCH --> REPO
    RUNNER --> MODELS
    REPO --> MODELS
```

## 4. Sequence: synchronous run (CLI)

The simplest path — `zeroshield run <experiment.json>` — everything happens in one process, one call stack:

```mermaid
sequenceDiagram
    participant User
    participant CLI as cli.commands.run_experiment
    participant Orch as orchestration.execute_and_generate_evidence
    participant Runner as runners.ExperimentRunner
    participant Policy as policies.SafetyPolicy
    participant Strat as strategies (baseline + mitigation)
    participant Repo as repositories.LocalEvidenceRepository

    User->>CLI: zeroshield run experiments/ZC-VPN-EXP-001.json
    CLI->>Orch: execute_and_generate_evidence(...)
    Orch->>Runner: run(...)
    Runner->>Policy: evaluate(experiment, execution_context)
    alt refused
        Policy-->>Runner: PolicyDecision(allowed=False)
        Runner-->>CLI: raises PolicyRefusalError
        CLI-->>User: prints COMPLETION FAILED, refused by safety policy
    else allowed
        Policy-->>Runner: PolicyDecision(allowed=True)
        Runner->>Strat: process() each test case (baseline, then mitigation)
        Strat-->>Runner: CaseResult per case
        Runner-->>Orch: ExperimentExecutionResult
        Orch->>Orch: calculate_metrics + compare (zeroshield.metrics)
        Orch->>Repo: save_run_evidence(baseline), save_run_evidence(mitigation), save_comparison
        Repo-->>Orch: manifest/comparison paths
        Orch-->>CLI: ValidationResult
        CLI-->>User: case counts, metrics, evidence path
    end
```

## 5. Sequence: asynchronous run (API + worker)

The API never executes an experiment itself — it queues a job and returns immediately; a separate worker process does the real work. This is the Producer–Consumer pattern from §2, and the only place `RunJobMessage`/`JobStore` (bookkeeping, not a core SRS-traced entity) are involved:

```mermaid
sequenceDiagram
    participant Client
    participant API as api.routes.experiments.submit_run
    participant MQ as RabbitMQ (zeroshield.experiment_runs)
    participant Worker as worker.main / worker.processor
    participant Svc as services.experiment_service.run_experiment

    Client->>API: POST /experiments/{id}/runs
    API->>API: JobStore.save(status=QUEUED)
    API->>MQ: publish RunJobMessage(job_id, experiment_id, execution_context)
    API-->>Client: 202 job_id, status=queued

    MQ->>Worker: deliver message
    Worker->>Worker: handle_message_body() - RunJobMessage.model_validate_json
    alt malformed message
        Worker-->>Worker: log + drop, ack anyway (never crashes the consume loop)
    else valid message
        Worker->>Worker: JobStore.save(status=RUNNING)
        Worker->>Svc: run_experiment(...) [same engine as the CLI path, §4]
        alt safety policy refuses
            Svc-->>Worker: raises PolicyRefusalError
            Worker->>Worker: JobStore.save(status=DENIED, error=reasons)
        else dataset/strategy unresolvable
            Svc-->>Worker: raises ExperimentServiceError
            Worker->>Worker: JobStore.save(status=FAILED, error=generic message)
        else success
            Svc-->>Worker: comparison report + evidence paths
            Worker->>Worker: JobStore.save(status=COMPLETED, result=summary)
        end
    end

    Client->>API: GET /jobs/{job_id} (poll)
    API-->>Client: current status (queued/running/completed/denied/failed)
```

## 6. Deployment view

The SRS's Figure 2 ("target deployment") deliberately scoped RabbitMQ, MinIO, and the dashboard as *deferred* infrastructure — "Phase 1 may run locally without the queue, object storage or dashboard." As of Milestone 23, this project has actually built all of it (Milestones 20–23), so the diagram below reflects what `docker-compose.yml` really runs today, not the SRS's original conservative baseline:

```mermaid
flowchart TB
    subgraph ClientFacing["Client-facing"]
        USER["User / Researcher"]
        SWAGGER["Swagger UI<br/>(localhost:8000/docs)"]
    end

    subgraph Containers["docker-compose.yml services"]
        API["api<br/>FastAPI :8000"]
        DASH["dashboard<br/>Streamlit :8502"]
        WORKER["worker<br/>:9200/metrics"]
        MQ["rabbitmq<br/>:5673 (AMQP), :15673 (mgmt UI)"]
        MINIO["minio<br/>:9002 (S3), :9003 (console)"]
        PROM["prometheus :9090"]
        GRAF["grafana :3000"]
    end

    subgraph HostMounts["Host bind mounts (shared, not container-local)"]
        RESULTS["results/"]
        JOBS["jobs/"]
        EXPORTS["overleaf_exports/"]
    end

    USER --> SWAGGER --> API
    USER --> DASH
    API --> MQ
    MQ --> WORKER
    WORKER --> RESULTS
    WORKER --> JOBS
    API --> JOBS
    DASH --> RESULTS
    API --> RESULTS
    DASH --> EXPORTS
    WORKER -.optional.-> MINIO
    PROM --> API
    PROM --> WORKER
    GRAF --> PROM
```

The CLI (`zeroshield` console script) is not shown as a container — it is always a local process, run directly against `results/`/`jobs/`/`experiments/` on the host, with or without Docker running.

## 7. What this document deliberately does not cover

- A step-by-step guided walkthrough of a real experiment end-to-end — that's Milestone 29 (Demonstration workflow).
- A requirement-by-requirement audit of which `FR-*`/`NFR-*`/`SAFE-*`/`AC-*` identifier is satisfied where — that's Milestone 30 (Final traceability and SRS compliance review).
- Command/argument/environment-variable reference — see [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) and [`docs/CONFIGURATION.md`](CONFIGURATION.md).
