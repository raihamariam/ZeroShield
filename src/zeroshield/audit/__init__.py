"""Immutable audit trail (V2 Phase 6, Step 3).

zeroshield.audit.service.AuditService.record() is the ONLY code path that
writes an audit_events row - no route/service ever inserts one directly via
the ORM, so "every audit event has actor/action/target/timestamp/request_id"
is enforced by there being exactly one call site, not by convention.
"""
