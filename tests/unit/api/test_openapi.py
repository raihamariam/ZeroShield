from fastapi.testclient import TestClient


def test_docs_ui_is_served(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger" in response.text.lower()


def test_openapi_schema_lists_all_endpoints(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert paths == {
        "/health",
        "/experiments",
        "/experiments/{experiment_id}",
        "/experiments/{experiment_id}/validate",
        "/experiments/{experiment_id}/runs",
        "/experiments/{experiment_id}/results",
        "/experiments/{experiment_id}/evidence",
        "/jobs/{job_id}",
        "/metrics",
        # V2 Phase 4: Professional Web Application
        "/jobs",
        "/jobs/{job_id}/events",
        "/experiments/{experiment_id}/evidence/bundle",
        "/system/status",
        # V2 Phase 2: Threat Intelligence & Prioritisation
        "/vulnerabilities",
        "/vulnerabilities/{cve_id}",
        "/vulnerabilities/{cve_id}/history",
        "/priority-queue",
        "/sources",
        "/integrations",
        "/intelligence/sync",
        "/intelligence/syncs",
        "/intelligence/syncs/{sync_id}",
        # V2 Phase 3: Advanced Validation Platform
        "/domain-packs",
        "/domain-packs/{pack_id}/templates",
        "/templates/{template_id}/{version}",
        "/datasets/generate",
        "/experiment-versions",
        "/experiment-versions/{version_id}",
        "/experiment-versions/{version_id}/approvals",
        "/experiment-versions/{version_id}/submit-review",
        "/experiment-versions/{version_id}/start-review",
        "/experiment-versions/{version_id}/approve",
        "/experiment-versions/{version_id}/reject",
        "/experiment-versions/{version_id}/retire",
        "/experiment-versions/{version_id}/runs",
        "/experiments/{experiment_id}/verdict",
        # V2 Phase 5: AI & Continuous Assurance
        "/ai-assessments",
        "/ai-assessments/{assessment_id}",
        "/ai-assessments/{assessment_id}/review",
        "/assets",
        "/assets/{asset_id}",
        "/controls",
        "/controls/{control_id}",
        "/controls/{control_id}/effectiveness",
        "/controls/{control_id}/versions",
        "/controls/{control_id}/regression/explain",
        "/revalidation",
        "/revalidation/scan",
        "/revalidation/{candidate_id}",
        "/revalidation/{candidate_id}/approve",
        "/revalidation/{candidate_id}/dismiss",
        "/vulnerabilities/{cve_id}/advisories",
        "/vulnerabilities/{cve_id}/affected-assets",
        "/vulnerabilities/{cve_id}/analyst/experiment-draft",
        "/vulnerabilities/{cve_id}/analyst/failure-pattern",
        "/vulnerabilities/{cve_id}/analyst/mitigation-gap",
        "/vulnerabilities/{cve_id}/analyst/similar",
        "/vulnerabilities/{cve_id}/analyst/template-recommendation",
        "/vulnerabilities/{cve_id}/correlations",
        # V2 Phase 6: Hardening & Final Local V2 Release
        "/auth/login",
        "/auth/logout",
        "/auth/me",
        "/users",
        "/users/{user_id}/role",
        "/users/{user_id}/active",
        "/audit-events",
    }
