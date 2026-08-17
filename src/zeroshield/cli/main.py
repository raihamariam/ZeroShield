import argparse
import sys
from pathlib import Path

from zeroshield.cli.commands import (
    CliError,
    compare_experiment,
    create_admin,
    run_experiment,
    validate_experiment,
    verify_evidence,
)
from zeroshield.policies import ExecutionContext

_CONTEXT_CHOICES = [c.value for c in ExecutionContext]
_CONTEXT_HELP = (
    "safety-policy execution context to evaluate against (default: experiment_run; "
    "use local_unit_test only for exercising an unapproved/draft experiment locally)"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zeroshield",
        description="ZeroShield Zero-Click Mitigation Validation Framework CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate-experiment",
        help="validate an experiment definition (schema, dataset, safety policy) without executing it",
    )
    validate_parser.add_argument("experiment_path", type=Path)
    validate_parser.add_argument(
        "--context", choices=_CONTEXT_CHOICES, default=ExecutionContext.EXPERIMENT_RUN.value, help=_CONTEXT_HELP
    )

    run_parser = subparsers.add_parser(
        "run", help="execute an experiment's baseline and mitigation and generate evidence"
    )
    run_parser.add_argument("experiment_path", type=Path)
    run_parser.add_argument(
        "--context", choices=_CONTEXT_CHOICES, default=ExecutionContext.EXPERIMENT_RUN.value, help=_CONTEXT_HELP
    )
    run_parser.add_argument("--baseline-run-id", default=None, help="override the auto-generated baseline run ID")
    run_parser.add_argument(
        "--mitigation-run-id", default=None, help="override the auto-generated mitigation run ID"
    )
    run_parser.add_argument(
        "--git-commit",
        default="0000000",
        help="hex commit reference recorded in evidence (default: placeholder; this repository has no commits yet)",
    )
    run_parser.add_argument("--results-dir", type=Path, default=Path("results"))

    compare_parser = subparsers.add_parser(
        "compare", help="display a baseline-vs-mitigation comparison from already-generated evidence"
    )
    compare_parser.add_argument("experiment_dir", type=Path, help="e.g. results/ZC-VPN-EXP-001")

    verify_parser = subparsers.add_parser(
        "verify-evidence", help="verify a run's evidence manifest, artefacts, and integrity hash"
    )
    verify_parser.add_argument("run_dir", type=Path, help="e.g. results/ZC-VPN-EXP-001/RUN-1234567890")

    create_admin_parser = subparsers.add_parser(
        "create-admin",
        help="bootstrap the first ADMIN user (V2 Phase 6) - requires DATABASE_URL, run once per fresh database",
    )
    create_admin_parser.add_argument("--username", required=True)
    create_admin_parser.add_argument(
        "--password", default=None, help="omit to generate and print a strong random password once"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "validate-experiment":
            ok = validate_experiment(args.experiment_path, context=ExecutionContext(args.context))
        elif args.command == "run":
            ok = run_experiment(
                args.experiment_path,
                context=ExecutionContext(args.context),
                baseline_run_id=args.baseline_run_id,
                mitigation_run_id=args.mitigation_run_id,
                git_commit=args.git_commit,
                results_root=args.results_dir,
            )
        elif args.command == "compare":
            ok = compare_experiment(args.experiment_dir)
        elif args.command == "verify-evidence":
            ok = verify_evidence(args.run_dir)
        elif args.command == "create-admin":
            generated_password = create_admin(args.username, args.password)
            print(f"Created ADMIN user '{args.username}'.")
            if generated_password is not None:
                print(
                    "Generated password (shown once - it is not stored anywhere and cannot be "
                    f"recovered): {generated_password}"
                )
            ok = True
        else:  # pragma: no cover - unreachable, argparse enforces the choices above
            raise AssertionError(f"unreachable: unknown command {args.command!r}")
    except CliError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0 if ok else 1
