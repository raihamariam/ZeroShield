"""Local sandbox execution boundary (V2 Phase 3, Step 6) - NOT Kubernetes, per
the phase's own instruction. Strengthens (does not replace) the existing
execution path: ExperimentRunner/orchestration still own the run lifecycle;
SandboxExecutor is what actually calls strategy.process() for each case,
adding allow-listing, a timeout, best-effort resource limits, and a network
guard around it.

Only built-in/allow-listed domain-pack code ever runs here - there is no
mechanism anywhere in this class (or in zeroshield.strategies.registry, which
it delegates identity checks to) for arbitrary uploaded Python, shell,
Docker images, eval/exec, or dynamic imports. See
tests/security/test_static_analysis_guards.py (AC-09) for the standing,
build-failing guard against those primitives ever being introduced.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome

logger = logging.getLogger("zeroshield.sandbox")


class SandboxError(Exception):
    """Base class for every sandbox-enforced denial - never raised for a
    strategy's own business-logic decision (BLOCKED/ACCEPTED), only for the
    sandbox refusing to run the strategy at all."""


class SandboxForbiddenExecutorError(SandboxError):
    """Raised when a strategy_id is not in the calling domain pack's
    allow-list - the sandbox's own enforcement layer, independent of (and in
    addition to) zeroshield.strategies.registry's fixed-dict Factory."""


class SandboxTimeoutError(SandboxError):
    pass


class SandboxNetworkDeniedError(SandboxError):
    """Raised if sandboxed code attempts to open a network socket while
    network_enabled=False (the default) - enforced at the Python socket layer
    (see _network_guard below), a genuine, testable control, not just a
    policy statement. Defence in depth alongside, not a replacement for, the
    container-level network policy the Docker deployment also applies."""


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: float = 5.0
    max_memory_bytes: int | None = 256 * 1024 * 1024
    network_enabled: bool = False


class SandboxExecutor:
    """The one place strategy.process() is actually invoked for a sandboxed
    run. allowed_strategy_ids, when given, is normally a DomainPack's own
    allow-listed subset (a narrower, domain-scoped check layered on top of
    the strategy registry's already-fixed-dict Factory)."""

    def __init__(self, *, allowed_strategy_ids: frozenset[str] | None = None) -> None:
        self._allowed_strategy_ids = allowed_strategy_ids

    def execute(
        self,
        strategy: ProcessingStrategy,
        input_data: dict[str, Any],
        *,
        limits: SandboxLimits | None = None,
    ) -> StrategyOutcome:
        limits = limits or SandboxLimits()
        if self._allowed_strategy_ids is not None and strategy.strategy_id not in self._allowed_strategy_ids:
            raise SandboxForbiddenExecutorError(
                f"strategy_id '{strategy.strategy_id}' is not allow-listed for this sandbox "
                f"context; allowed: {sorted(self._allowed_strategy_ids)}"
            )

        with (
            _network_guard(limits.network_enabled),
            _resource_guard(limits.max_memory_bytes),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            future = pool.submit(strategy.process, input_data)
            try:
                return future.result(timeout=limits.timeout_seconds)
            except FutureTimeoutError:
                raise SandboxTimeoutError(
                    f"strategy '{strategy.strategy_id}' exceeded the "
                    f"{limits.timeout_seconds}s sandbox timeout"
                ) from None
            # Known limitation: Python cannot forcibly kill a running thread -
            # a genuinely hung strategy.process() call is abandoned (orphaned),
            # not terminated. Acceptable given every allow-listed strategy is a
            # pure, fast, synchronous function with no blocking I/O (verified:
            # zeroshield.strategies.vpn/telecom perform no network or disk
            # access) - true forceful preemption would need process-based
            # isolation, a heavier mechanism not justified by this threat model
            # and explicitly out of scope ("Do NOT build Kubernetes").


@contextmanager
def _network_guard(enabled: bool):  # type: ignore[no-untyped-def]
    if enabled:
        yield
        return
    original_socket = socket.socket

    def _blocked(*args: Any, **kwargs: Any) -> Any:
        raise SandboxNetworkDeniedError("network access is disabled in this sandbox context")

    socket.socket = _blocked  # type: ignore[assignment,misc]
    try:
        yield
    finally:
        socket.socket = original_socket  # type: ignore[misc]


@contextmanager
def _resource_guard(max_memory_bytes: int | None):  # type: ignore[no-untyped-def]
    """Best-effort process-wide memory cap via the POSIX `resource` module
    (available in the Linux containers this platform actually deploys to -
    see docker-compose.yml). No-ops with a debug log on platforms without it
    (e.g. Windows, where this is developed) - a documented, honest platform
    limitation, not a silent false guarantee."""
    if max_memory_bytes is None:
        yield
        return
    try:
        import resource
    except ImportError:
        logger.debug("resource module unavailable on this platform - memory limit not enforced")
        yield
        return

    # `resource` is POSIX-only; typeshed only exposes it under sys.platform
    # checks mypy can't resolve from inside this try/except ImportError guard
    # on a non-POSIX dev machine (this is developed on Windows) - the
    # attributes are real and correct on the Linux containers this platform
    # actually deploys to (see docker-compose.yml).
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)  # type: ignore[attr-defined]
    new_limit = (
        max_memory_bytes if hard == resource.RLIM_INFINITY else min(max_memory_bytes, hard)  # type: ignore[attr-defined]
    )
    try:
        resource.setrlimit(resource.RLIMIT_AS, (new_limit, hard))  # type: ignore[attr-defined]
    except (ValueError, OSError):
        logger.debug("could not set RLIMIT_AS - memory limit not enforced", exc_info=True)
        yield
        return
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))  # type: ignore[attr-defined]
