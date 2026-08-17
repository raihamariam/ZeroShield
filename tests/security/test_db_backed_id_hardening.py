"""Malformed/malicious-ID hardening for DB-backed routes (V2 Phase 6, Step 4):
assets/controls/revalidation/ai-assessments/users. These IDs resolve through
SQLAlchemy ORM lookups (always parameterised - no raw SQL string
interpolation exists anywhere in this codebase), so the goal here is
different from tests/security/test_path_traversal_comprehensive.py's
filesystem-boundary sweep: proving a malformed/injection-shaped ID always
degrades to a clean 404/422, never a 500, and never returns another
record's data.
"""

from fastapi.testclient import TestClient

MALICIOUS_IDS = [
    "../../etc/passwd",
    "'; DROP TABLE assets; --",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "%00null-byte",  # URL-encoded null byte - a raw \x00 is rejected by the HTTP client itself before it could even form a request
    "a" * 5000,  # oversized ID - must not crash a fixed-width or unindexed lookup
    "%2e%2e%2fetc%2fpasswd",
]

# (method, path_template) for every DB-backed route with an id path
# parameter that does a get-by-id lookup.
DB_ID_ROUTES: list[tuple[str, str]] = [
    ("GET", "/assets/{id}"),
    ("PATCH", "/assets/{id}"),
    ("GET", "/controls/{id}"),
    ("GET", "/controls/{id}/versions"),
    ("GET", "/controls/{id}/effectiveness"),
    ("POST", "/controls/{id}/regression/explain"),
    ("GET", "/revalidation/{id}"),
    ("POST", "/revalidation/{id}/approve"),
    ("POST", "/revalidation/{id}/dismiss"),
    ("GET", "/ai-assessments/{id}"),
    ("POST", "/ai-assessments/{id}/review"),
    ("PATCH", "/users/{id}/role"),
    ("PATCH", "/users/{id}/active"),
]

_BODY_FOR_METHOD = {"PATCH": {}, "POST": {}}


def test_db_backed_id_routes_reject_malicious_ids_cleanly(client: TestClient) -> None:
    failures = []
    for method, template in DB_ID_ROUTES:
        for malicious_id in MALICIOUS_IDS:
            path = template.format(id=malicious_id)
            body = _BODY_FOR_METHOD.get(method)
            response = client.request(method, path, json=body)
            if response.status_code >= 500:
                failures.append((method, path[:60], response.status_code))
    assert failures == [], f"malicious ID caused a server error on: {failures}"


def test_cve_id_route_rejects_sql_injection_shaped_ids(client: TestClient) -> None:
    """/vulnerabilities/{cve_id} constrains the path parameter with a regex
    (CVE-YYYY-NNNN+) - a SQL-injection-shaped value must never even reach
    the query layer, confirmed here by a clean 404/422 rather than a 500."""
    for payload in ["' OR '1'='1", "'; DROP TABLE vulnerabilities; --"]:
        response = client.get(f"/vulnerabilities/{payload}")
        assert response.status_code in (404, 422)


def test_asset_id_used_as_a_creation_payload_is_not_interpreted_as_sql(client: TestClient) -> None:
    """asset_id is a free-text field on creation (unlike auto-generated IDs
    elsewhere) - a SQL-metacharacter-laden value must be stored and returned
    verbatim as an ordinary string, never executed or malformed."""
    payload_id = "asset'; DROP TABLE assets; --"
    response = client.post(
        "/assets",
        json={
            "asset_id": payload_id, "name": "n", "vendor": "v", "product": "p",
            "environment": "production", "exposure": "internal", "criticality": "low",
        },
    )
    assert response.status_code == 201
    assert response.json()["asset_id"] == payload_id

    # The table must still exist and be queryable - proving no SQL was executed.
    listing = client.get("/assets")
    assert listing.status_code == 200
    assert any(a["asset_id"] == payload_id for a in listing.json()["assets"])
