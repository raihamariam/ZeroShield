# Importing these registers the concrete VPN/Telecom templates as a side
# effect (register_template() calls at module load) - the same
# import-time-registration pattern zeroshield.domain_packs.registry relies on.
from zeroshield.templates import telecom_templates as _telecom_templates  # noqa: F401
from zeroshield.templates import vpn_templates as _vpn_templates  # noqa: F401
from zeroshield.templates.models import ValidationTemplate
from zeroshield.templates.registry import (
    DuplicateTemplateError,
    UnknownTemplateError,
    latest_version,
    list_templates,
    register_template,
    resolve_template,
)

__all__ = [
    "DuplicateTemplateError",
    "UnknownTemplateError",
    "ValidationTemplate",
    "latest_version",
    "list_templates",
    "register_template",
    "resolve_template",
]
