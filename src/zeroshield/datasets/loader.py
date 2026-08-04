import hashlib
import json
from pathlib import Path

from zeroshield.models import TestSet


def load_test_set(path: Path) -> tuple[TestSet, str]:
    raw_bytes = path.read_bytes()
    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
    data = json.loads(raw_bytes)
    test_set = TestSet.model_validate(data)
    return test_set, sha256_hex
