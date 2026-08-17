"""Password hashing (V2 Phase 6, Step 1).

Argon2id via the `argon2-cffi` package (OWASP's current top recommendation
for new applications, over bcrypt/PBKDF2) - memory-hard, resists GPU/ASIC
cracking. `PasswordHasher()`'s defaults (time_cost=3, memory_cost=64MiB,
parallelism=4 as of argon2-cffi 23.x) are used as-is rather than hand-tuned,
since second-guessing a security library's own defaults without a measured
reason is how mistakes get made.

Never logged, never included in an audit event, never returned from any API
response - password_hash only ever exists inside zeroshield.auth.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

# OWASP ASVS-aligned minimum - rejected at the API boundary (schemas.py),
# not just documented, so a weak password can never reach the hasher.
MIN_PASSWORD_LENGTH = 12


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, plaintext)
    except VerifyMismatchError:
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the hash was produced with older/weaker parameters than the
    hasher's current defaults - callers may choose to transparently
    re-hash on next successful login (not automated here, since it is
    optional operational polish, not a security requirement)."""
    return _hasher.check_needs_rehash(password_hash)
