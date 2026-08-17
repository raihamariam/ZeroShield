"""Continuous assurance: asset inventory (Step 7), control/control-version/
control-validation history (Step 8), control effectiveness (Step 9),
deterministic regression detection (Step 10), the revalidation-candidate
workflow (Step 11), and persisted AI assessment records (Step 2) - the
"accumulates knowledge over time" half of V2 Phase 5.

Deliberately a small, flat package: one repository class over one small set
of tables (zeroshield.db.models), mirroring how
zeroshield.intelligence.repository.VulnerabilityRepository is one
repository over several related tables rather than one repository per
table. Nothing here executes a run, approves a version, or writes evidence
- see zeroshield.assurance.repository's docstring for exactly what each
table records and who is allowed to write to it.
"""
