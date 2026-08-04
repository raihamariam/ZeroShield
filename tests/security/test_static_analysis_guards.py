"""Static guards that don't require running any code (Milestone 26):

- SAFE-006 ("secrets and real credentials are prohibited from test
  datasets"): scans every real experiment/dataset JSON file this project
  ships for secret-shaped strings. Not implemented as a runtime policy rule
  (there is nothing to "run" - experiments/test_data are static, checked-in
  files), so it is enforced here instead, the same way a pre-commit secret
  scanner would.
- AC-09 ("... refused by safety policy" / dangerous-primitive avoidance):
  greps src/ for code-execution/deserialization primitives that would make
  policy refusal or sandboxing meaningless if ever introduced
  (eval/exec/os.system/subprocess with shell=True/pickle/__import__). None
  are used anywhere in this project today; this test is a tripwire against
  ever adding one without a deliberate, reviewed allowlist entry.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DATASET_FILES = [
    *sorted((REPO_ROOT / "experiments").glob("*.json")),
    *sorted((REPO_ROOT / "test_data").rglob("*.json")),
]

# Deliberately broad and prone to false positives on random hex/base64-looking
# test data - that's the correct failure mode for a secret scanner (SAFE-006
# is a hard prohibition; a false positive costs a one-line allowlist entry, a
# false negative costs a leaked credential).
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key_assignment": re.compile(
        r"""(?i)(api[_-]?key|secret|token|password|passwd)["']?\s*[:=]\s*["'][^"'\s]{8,}["']"""
    ),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "bearer_token": re.compile(r"(?i)bearer\s+[a-z0-9._-]{20,}"),
}

# (dataset_relative_path, pattern_name) pairs reviewed and confirmed to be
# synthetic test fixtures, not real secrets - see the file for context.
ALLOWLIST: set[tuple[str, str]] = set()


def _relative_findings() -> list[tuple[str, str, str]]:
    findings = []
    for path in DATASET_FILES:
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for name, pattern in SECRET_PATTERNS.items():
            if (rel, name) in ALLOWLIST:
                continue
            match = pattern.search(text)
            if match:
                findings.append((rel, name, match.group(0)))
    return findings


def test_dataset_files_exist_to_scan() -> None:
    """Guards against this test silently scanning zero files if the dataset
    layout ever moves - a scan that finds nothing because it looked nowhere
    is not evidence of SAFE-006 compliance."""
    assert len(DATASET_FILES) >= 4


def test_experiment_and_dataset_json_files_contain_no_secret_shaped_strings() -> None:
    findings = _relative_findings()
    assert findings == [], (
        "SAFE-006 violation: secret-shaped strings found in checked-in test data: "
        f"{findings}"
    )


def test_dataset_json_files_are_syntactically_valid() -> None:
    """Sanity check that the files above are genuinely being read as intended,
    not silently matching zero real content due to a bad glob."""
    for path in DATASET_FILES:
        json.loads(path.read_text(encoding="utf-8"))


DANGEROUS_PATTERNS: dict[str, re.Pattern[str]] = {
    "eval": re.compile(r"\beval\("),
    "exec": re.compile(r"\bexec\("),
    "os_system": re.compile(r"\bos\.system\("),
    "subprocess_shell_true": re.compile(r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True"),
    "pickle": re.compile(r"\bpickle\."),
    "dunder_import": re.compile(r"__import__\("),
}

# (source_relative_path, pattern_name) pairs deliberately reviewed and
# accepted - empty today; adding a dangerous primitive requires adding a
# justified entry here, making the decision visible in code review.
DANGEROUS_PATTERN_ALLOWLIST: set[tuple[str, str]] = set()


def test_source_tree_contains_no_dangerous_execution_primitives() -> None:
    findings = []
    for path in sorted((REPO_ROOT / "src").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for name, pattern in DANGEROUS_PATTERNS.items():
            if (rel, name) in DANGEROUS_PATTERN_ALLOWLIST:
                continue
            if pattern.search(text):
                findings.append((rel, name))
    assert findings == [], f"AC-09 tripwire: dangerous primitive(s) found: {findings}"
