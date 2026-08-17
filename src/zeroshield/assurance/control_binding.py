"""Derives which Control/ControlVersion a completed run belongs to, from
nothing but the ExperimentDefinition that ran (V2 Phase 5, Step 8).

ExperimentDefinition predates Domain Packs/Templates (Phase 1) and never
carries a domain_pack_id/template_id itself - both V1 hand-authored and
Studio-built experiments only carry `domain` and `mitigation_strategy`
directly. This resolves the same thing that build_experiment_draft already
knows for Studio-built experiments, for ANY experiment: the domain pack ID
is just the lowercased domain (zeroshield.domain_packs' pack_id convention
- "vpn"/"telecom"), and the template is recovered by finding the one
registered template in that pack whose allow-listed mitigation strategies
include this experiment's - a real, deterministic lookup against the
existing template registry, never a guess. Falls back to "unknown" only if
no matching template is registered (e.g. a future domain pack this session
never templated), so a control-version record is always creatable."""

from dataclasses import dataclass

from zeroshield.assurance.models import Control, ControlVersion
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.models import ExperimentDefinition
from zeroshield.templates import list_templates


@dataclass(frozen=True)
class ControlBinding:
    control: Control
    version: ControlVersion


def bind_experiment_to_control(repo: AssuranceRepository, experiment: ExperimentDefinition) -> ControlBinding:
    domain_pack_id = experiment.domain.value.lower()
    template_id = "unknown"
    template_version = experiment.version

    for template in list_templates(domain_pack_id):
        if experiment.mitigation_strategy in template.allowed_mitigation_strategies:
            template_id = template.template_id
            template_version = template.version
            break

    control = repo.get_or_create_control(
        domain=experiment.domain.value,
        mitigation_strategy_id=experiment.mitigation_strategy,
        name=f"{experiment.domain.value} {experiment.mitigation_strategy}",
    )
    version = repo.get_or_create_control_version(
        control_id=control.control_id,
        version_label=experiment.version,
        domain_pack_id=domain_pack_id,
        template_id=template_id,
        template_version=template_version,
    )
    return ControlBinding(control=control, version=version)
