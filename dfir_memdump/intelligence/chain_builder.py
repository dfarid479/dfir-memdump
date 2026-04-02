"""
Attack Chain Reconstructor.

Groups all findings by their MITRE ATT&CK tactic, orders them along the
standard kill chain, and generates a plain-English narrative for each
stage that was observed.

Output is a list of ChainStep objects — one per observed tactic stage —
sorted from earliest (Initial Access) to latest (Impact) in a typical
intrusion timeline.
"""

from __future__ import annotations
import logging

from dfir_memdump.models import ChainStep, Finding

logger = logging.getLogger(__name__)

# Kill chain stage order.  Matches the MITRE ATT&CK Enterprise kill-chain.
# Tactics not in this list are appended at the end under "Other".
_STAGE_ORDER: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Map tactic strings (from MitreRef.tactic) to normalised stage names.
# A finding can have slash-separated tactics ("Defense Evasion / Privilege Escalation")
# — we assign it to the first matching stage.
_TACTIC_NORMALIZE: dict[str, str] = {
    # Lower-case keys → canonical stage name
    "initial access":             "Initial Access",
    "execution":                  "Execution",
    "persistence":                "Persistence",
    "privilege escalation":       "Privilege Escalation",
    "defense evasion":            "Defense Evasion",
    "credential access":          "Credential Access",
    "discovery":                  "Discovery",
    "lateral movement":           "Lateral Movement",
    "collection":                 "Collection",
    "command and control":        "Command and Control",
    "exfiltration":               "Exfiltration",
    "impact":                     "Impact",
}

# Per-stage narrative templates.
# {count} = finding count, {titles} = comma-separated titles (first 3)
_NARRATIVES: dict[str, str] = {
    "Initial Access":      "The attacker gained a foothold via {count} indicator(s): {titles}.",
    "Execution":           "{count} execution-phase indicator(s) suggest the attacker ran code on the host: {titles}.",
    "Persistence":         "Persistence mechanisms were observed ({count} indicator(s)): {titles}.",
    "Privilege Escalation":"{count} privilege escalation indicator(s) detected, suggesting the attacker elevated access: {titles}.",
    "Defense Evasion":     "{count} defense evasion technique(s) observed — the attacker attempted to avoid detection: {titles}.",
    "Credential Access":   "{count} credential-access indicator(s) found — credentials may have been harvested: {titles}.",
    "Discovery":           "Host and network discovery activity detected ({count} indicator(s)): {titles}.",
    "Lateral Movement":    "Lateral movement indicators suggest the attacker pivoted to other systems ({count} indicator(s)): {titles}.",
    "Collection":          "{count} collection-phase indicator(s) found — data may have been staged: {titles}.",
    "Command and Control": "{count} C2 indicator(s) detected — active communication with attacker infrastructure: {titles}.",
    "Exfiltration":        "{count} exfiltration indicator(s) found — data may have been removed from the host: {titles}.",
    "Impact":              "{count} impact-stage indicator(s) detected — destructive activity (ransomware / data destruction) may have occurred: {titles}.",
}


def build_attack_chain(findings: list[Finding]) -> list[ChainStep]:
    """
    Group findings by MITRE tactic, order by kill chain stage, and return
    a list of ChainStep objects ready to be embedded in the triage report.
    """
    # Stage → collected data
    stage_findings:  dict[str, list[str]] = {}
    stage_mitre_ids: dict[str, set[str]]  = {}

    for f in findings:
        if not f.mitre:
            continue
        # Handle slash-separated tactics ("Defense Evasion / Privilege Escalation")
        tactics = [t.strip() for t in f.mitre.tactic.split("/")]
        stage = None
        for tactic in tactics:
            stage = _TACTIC_NORMALIZE.get(tactic.lower())
            if stage:
                break
        if stage is None:
            stage = "Other"

        stage_findings.setdefault(stage, []).append(f.title)
        stage_mitre_ids.setdefault(stage, set()).add(f.mitre.technique_id)

    if not stage_findings:
        return []

    steps: list[ChainStep] = []
    observed_stages = set(stage_findings.keys())

    # Ordered stages first
    for order, stage in enumerate(_STAGE_ORDER):
        if stage not in observed_stages:
            continue
        titles_list = stage_findings[stage]
        preview_titles = ", ".join(t[:60] for t in titles_list[:3])
        if len(titles_list) > 3:
            preview_titles += f", … (+{len(titles_list) - 3} more)"
        narrative_tmpl = _NARRATIVES.get(stage, "{count} finding(s) in this stage: {titles}.")
        narrative = narrative_tmpl.format(count=len(titles_list), titles=preview_titles)
        steps.append(ChainStep(
            stage       = stage,
            stage_order = order,
            findings    = titles_list,
            mitre_ids   = sorted(stage_mitre_ids.get(stage, set())),
            narrative   = narrative,
        ))

    # Any unrecognised tactics appended at the end
    for stage in sorted(observed_stages - set(_STAGE_ORDER)):
        titles_list = stage_findings[stage]
        steps.append(ChainStep(
            stage       = stage,
            stage_order = len(_STAGE_ORDER),
            findings    = titles_list,
            mitre_ids   = sorted(stage_mitre_ids.get(stage, set())),
            narrative   = f"{len(titles_list)} finding(s) in this stage: {', '.join(t[:60] for t in titles_list[:3])}.",
        ))

    logger.info("ChainBuilder: %d kill-chain stages observed", len(steps))
    return steps
