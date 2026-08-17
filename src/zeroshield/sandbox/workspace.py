"""Temporary writable workspace for a sandboxed run (Step 6: "temporary
writable workspace... cleanup"). The base environment (source, installed
packages) is never written to by sandboxed code - only this directory is
writable, and it is always removed on exit, success or failure."""

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def sandbox_workspace(*, prefix: str = "zeroshield-sandbox-") -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp_dir:
        yield Path(tmp_dir)
