"""Template registry, keyed by (template_id, version) - never overwritten, so
"historical experiments must keep their original template version" (Step 2)
holds structurally: registering a new version of a template_id never removes
or mutates an older one. Populated at import time by the domain-specific
template modules (vpn_templates.py, telecom_templates.py); this module holds
no domain knowledge itself.
"""

from zeroshield.templates.models import ValidationTemplate

_REGISTRY: dict[tuple[str, str], ValidationTemplate] = {}


class UnknownTemplateError(Exception):
    pass


class DuplicateTemplateError(Exception):
    """A given (template_id, version) pair was already registered - versions
    are append-only, never replaced in place."""


def register_template(template: ValidationTemplate) -> None:
    key = (template.template_id, template.version)
    if key in _REGISTRY:
        raise DuplicateTemplateError(
            f"template '{template.template_id}' version '{template.version}' is already registered"
        )
    _REGISTRY[key] = template


def resolve_template(template_id: str, version: str) -> ValidationTemplate:
    try:
        return _REGISTRY[(template_id, version)]
    except KeyError:
        raise UnknownTemplateError(
            f"no registered template '{template_id}' version '{version}'; known versions: "
            f"{sorted(v for t, v in _REGISTRY if t == template_id)}"
        ) from None


def latest_version(template_id: str) -> ValidationTemplate:
    matches = sorted((v for t, v in _REGISTRY if t == template_id), key=_version_key)
    if not matches:
        raise UnknownTemplateError(f"no registered template with id '{template_id}'")
    return _REGISTRY[(template_id, matches[-1])]


def list_templates(domain_pack_id: str | None = None) -> list[ValidationTemplate]:
    templates = list(_REGISTRY.values())
    if domain_pack_id is not None:
        templates = [t for t in templates if t.domain_pack_id == domain_pack_id]
    return sorted(templates, key=lambda t: (t.template_id, _version_key(t.version)))


def _version_key(version: str) -> tuple[float, ...]:
    """Best-effort numeric sort for dotted semver-shaped strings ('1.0.0' <
    '1.1.0' < '2.0.0'); falls back to string comparison for anything else."""
    parts: list[float] = []
    for segment in version.split("."):
        if segment.isdigit():
            parts.append(int(segment))
        else:
            return (float("inf"),)  # non-numeric versions sort last, deterministically
    return tuple(parts)
