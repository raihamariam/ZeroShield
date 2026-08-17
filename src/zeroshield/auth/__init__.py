"""Local authentication and RBAC (V2 Phase 6, Steps 1-2).

A deliberately small, self-contained local auth system - opaque server-side
sessions (never JWTs, so a session can always be revoked by deleting one
row), Argon2id password hashing (OWASP's current recommendation), and four
fixed roles. No SSO/OAuth/enterprise identity federation - out of scope by
the phase brief's own "do not over-engineer" instruction.
"""
