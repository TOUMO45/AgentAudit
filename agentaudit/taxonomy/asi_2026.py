"""OWASP Top 10 for Agentic Applications (2026) — the single source of truth
for mapping every AgentAudit detector ``rule_id`` to one or more ASI codes.

The scorecard HTML, the SARIF export and the CLI text output all import their
ASI data from here. Nothing else in the codebase should hard-code an ASI code.

Provenance
----------
Framework: **OWASP Top 10 for Agentic Applications**, published **2025-12-09**
by the OWASP GenAI Security Project (OWASP Foundation).

The one-line category descriptions below are cross-checked across three
independent public renderings (they agree):

* OWASP GenAI Security Project — launch announcement (2025-12-09):
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
* Modulos Governance Guide — "OWASP Top 10 for Agentic Applications (2026)":
  https://docs.modulos.ai/frameworks/owasp-top-10-agentic
* DeepTeam docs — "OWASP Top 10 for Agents 2026":
  https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications

See ``references/asi_2026_mapping.md`` for the full per-rule justification and
the two deliberately-unmapped findings.

Caveats kept visible on purpose
-------------------------------
* ``memory-encryption-ttl`` -> ASI06 is an **ADJACENT** fit, not an exact one
  (see :data:`ADJACENCY_NOTES`).
* ``guardrails-attached`` and ``runtime-network-mode`` are **NOT mapped** — a
  forced mapping would overstate the fit (see :data:`UNMAPPED`).
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# The taxonomy itself
# --------------------------------------------------------------------------- #
TAXONOMY_NAME = "OWASP-ASI-2026"
# Stable, arbitrary UUIDv4 identifying this taxonomy component in SARIF output.
TAXONOMY_GUID = "6d3a9c74-5f21-4c8e-b0d1-2a7e9f4c1b30"
TAXONOMY_VERSION = "2026"
TAXONOMY_RELEASE_UTC = "2025-12-09"
TAXONOMY_ORG = "OWASP GenAI Security Project"
TAXONOMY_URI = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"

# code -> (title, one-line description). Insertion order == ASI01..ASI10, and
# that order is also the SARIF ``taxa`` array order (index 0 == ASI01).
ASI: dict[str, tuple[str, str]] = {
    "ASI01": (
        "Agent Goal Hijack",
        "Attackers manipulate agent goals, plans, or decision paths through direct "
        "or indirect instruction injection, causing the agent to pursue unintended "
        "or malicious objectives.",
    ),
    "ASI02": (
        "Tool Misuse & Exploitation",
        "Agents misuse or abuse tools through unsafe composition, recursion, or "
        "excessive execution, causing harmful side effects despite having valid "
        "permissions.",
    ),
    "ASI03": (
        "Agent Identity & Privilege Abuse",
        "Delegated authority, ambiguous agent identity, or trust assumptions lead "
        "to unauthorized actions; leaked credentials let the agent operate beyond "
        "its authorized scope.",
    ),
    "ASI04": (
        "Agentic Supply Chain Vulnerabilities",
        "Compromise of external agents, tools, schemas, registries, or prompts that "
        "agents dynamically trust or import.",
    ),
    "ASI05": (
        "Unexpected Code Execution",
        "Agent-generated or agent-triggered code executes without sufficient "
        "validation or isolation; a sandbox boundary fails and arbitrary code runs.",
    ),
    "ASI06": (
        "Memory & Context Poisoning",
        "Injection or leakage of persistent memory, retrieval, or contextual state "
        "that influences the agent's future reasoning or actions.",
    ),
    "ASI07": (
        "Insecure Inter-Agent Communication",
        "Messages exchanged between agents, planners, and executors are spoofed, "
        "replayed, or unauthenticated.",
    ),
    "ASI08": (
        "Cascading Failures",
        "A small error or compromise in one agent propagates through connected "
        "systems, multiplying impact.",
    ),
    "ASI09": (
        "Human-Agent Trust Exploitation",
        "Exploiting human over-reliance on agents through misleading explanations "
        "or authority framing, leading humans to approve harmful actions.",
    ),
    "ASI10": (
        "Rogue Agents",
        "An agent acts beyond its intended objectives due to goal drift, collusion, "
        "concealment, or emergent / compromised behavior.",
    ),
}
ASI_ORDER: list[str] = list(ASI)

# --------------------------------------------------------------------------- #
# rule_id -> ASI codes (primary first). Justifications: references/asi_2026_mapping.md
# --------------------------------------------------------------------------- #
RULE_ASI: dict[str, list[str]] = {
    # architectural / static trust graph
    "idor-in-agent": ["ASI03", "ASI02"],
    "confused-deputy": ["ASI02", "ASI05"],
    "ssrf-via-tool-param": ["ASI02", "ASI03"],
    "excessive-agency": ["ASI02", "ASI05"],
    "secret-in-prompt": ["ASI03"],
    "exfiltration-capability-pair": ["ASI02", "ASI03"],
    "tool-rug-pull": ["ASI04", "ASI06"],
    # behavioral
    "overbroad-authority-in-prompt": ["ASI01", "ASI03"],
    # cloud posture
    "iam-least-privilege": ["ASI03"],
    "runtime-imdsv2": ["ASI03", "ASI02"],
    # ADJACENT fit — kept, with the caveat surfaced everywhere (see ADJACENCY_NOTES).
    "memory-encryption-ttl": ["ASI06"],
}

# Deliberately NOT mapped. Forcing these into an ASI category would overstate
# the fit. A test asserts every layer detector is here OR in RULE_ASI.
UNMAPPED: dict[str, str] = {
    "guardrails-attached": (
        "Cross-cutting mitigation. Bedrock Guardrails defend against ASI01, ASI05 "
        "and harmful-content simultaneously; the absence of a defense-in-depth "
        "control is not itself an instance of a single ASI category."
    ),
    "runtime-network-mode": (
        "Infrastructure posture. An AgentCore runtime exposed with "
        "networkMode=PUBLIC is a cloud-network hardening finding, not one of the "
        "ten agent-centric risk classes; mapping it to ASI03/ASI08 would overstate "
        "the fit."
    ),
}

# Extra context surfaced in user-facing docs and comments for imperfect fits.
ADJACENCY_NOTES: dict[str, str] = {
    "memory-encryption-ttl": (
        "Mapped to ASI06 (Memory & Context Poisoning) for the 'leakage of "
        "contextual state' half of the definition. The fit is ADJACENT, not exact: "
        "unencrypted / un-expiring agent memory is also a generic data-at-rest "
        "issue that is not unique to agentic systems."
    ),
}


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #
def asi_for(rule_id: str) -> list[str]:
    """ASI codes for a rule_id, primary first. ``[]`` if unmapped/unknown."""
    return list(RULE_ASI.get(rule_id, []))


def is_unmapped(rule_id: str) -> bool:
    return rule_id in UNMAPPED


def unmapped_reason(rule_id: str) -> str:
    return UNMAPPED.get(rule_id, "")


def adjacency_note(rule_id: str) -> str:
    return ADJACENCY_NOTES.get(rule_id, "")


def title_for(code: str) -> str:
    return ASI[code][0]


def describe(code: str) -> str:
    return ASI[code][1]


def taxon_index(code: str) -> int:
    """Position of ``code`` in the SARIF ``taxa`` array (ASI01 -> 0)."""
    return ASI_ORDER.index(code)


def label_for(rule_id: str) -> str:
    """Compact chip / CLI label, e.g. ``"ASI03·ASI02"``. Empty when unmapped."""
    return "·".join(asi_for(rule_id))


def tooltip_for(rule_id: str) -> str:
    """Human tooltip: ``"ASI03 Agent Identity & Privilege Abuse · ASI02 …"``."""
    return " · ".join(f"{c} {title_for(c)}" for c in asi_for(rule_id))


def known_rule_ids() -> set[str]:
    """Every rule_id this module has an explicit opinion about (mapped OR
    deliberately unmapped). The taxonomy test asserts the layer detectors are a
    subset of this."""
    return set(RULE_ASI) | set(UNMAPPED)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 native taxonomy helpers
# --------------------------------------------------------------------------- #
def sarif_taxonomy_component() -> dict:
    """The ``run.taxonomies[]`` toolComponent for OWASP-ASI-2026."""
    return {
        "name": TAXONOMY_NAME,
        "guid": TAXONOMY_GUID,
        "organization": TAXONOMY_ORG,
        "shortDescription": {
            "text": "OWASP Top 10 for Agentic Applications (2026) — ASI01–ASI10."
        },
        "informationUri": TAXONOMY_URI,
        "version": TAXONOMY_VERSION,
        "releaseDateUtc": TAXONOMY_RELEASE_UTC,
        "isComprehensive": True,
        "taxa": [
            {"id": code, "name": title, "shortDescription": {"text": desc}}
            for code, (title, desc) in ASI.items()
        ],
    }


def sarif_taxonomy_reference() -> dict:
    """A ``toolComponentReference`` for ``driver.supportedTaxonomies``."""
    return {"name": TAXONOMY_NAME, "guid": TAXONOMY_GUID}


def sarif_taxon_reference(code: str) -> dict:
    """A ``reportingDescriptorReference`` pointing at one ASI taxon."""
    return {
        "id": code,
        "index": taxon_index(code),
        "toolComponent": {"name": TAXONOMY_NAME, "guid": TAXONOMY_GUID},
    }


def sarif_rule_relationships(rule_id: str) -> list[dict]:
    """``reportingDescriptor.relationships`` — one ``relevant`` edge per ASI code."""
    return [
        {"target": sarif_taxon_reference(code), "kinds": ["relevant"]}
        for code in asi_for(rule_id)
    ]


def sarif_result_taxa(rule_id: str) -> list[dict]:
    """``result.taxa`` — the same taxa, referenced from the result itself."""
    return [sarif_taxon_reference(code) for code in asi_for(rule_id)]
