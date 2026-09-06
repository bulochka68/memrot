"""Target-agnostic vulnerability taxonomy: OWASP Agent Memory Guard (primary)
plus a best-effort MITRE ATLAS technique cross-reference (secondary).

Why a second taxonomy alongside ``rule_ids``/``taxonomy`` on
:class:`~memrot.models.AttackVariant`: those two fields are useful but
both have a genericity problem for the stated goal of running this harness
against *any* agent, not just the bank stand this repo ships fixtures for.

* ``rule_ids`` links to ``mcp_audit``'s rule catalogue (``MEM-02``, ...),
  which was authored *for this stand's own control surface* -- a new target
  has no such rule catalogue to link against.
* ``taxonomy`` (MITRE ATLAS ids) is a solid, target-agnostic framework, but
  this repo has so far only ever populated two ids (``AML.T0051``,
  ``AML.T0070``) and there is no registry describing what they mean, so a
  reader can't tell which categories exist without grepping catalog JSON.

``owasp_amg_category`` fixes both problems: it is a small, fixed, published
vocabulary (OWASP's Agent Memory Guard project, mapping to ASI06 -- "Memory &
Context Poisoning" -- in the OWASP Top 10 for Agentic Applications) that says
nothing about any particular target, so a prompt pool tagged with it is
reusable against any memory-bearing agent. ``rule_ids``/ATLAS ``taxonomy``
stay in place as optional secondary tags for cross-referencing a specific
audit or framework mapping when one exists -- they are not replaced.

MITRE ATLAS technique ids below are limited to the ones this project has
already relied on plus a small number of additional ids for adjacent
tool/plugin techniques; unlike the OWASP AMG categories (which are exhaustive
here), this is *not* claimed to be a complete ATLAS mapping -- add ids as
they are verified against the live ATLAS matrix rather than guessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class TaxonomyCategory:
    slug: str
    title: str
    owasp_amg_id: str          # OWASP Agent Memory Guard category id (maps to ASI06.*)
    description: str
    atlas_technique_ids: Tuple[str, ...] = ()   # best-effort MITRE ATLAS cross-reference


OWASP_AMG_CATEGORIES: Dict[str, TaxonomyCategory] = {
    "memory_prompt_injection": TaxonomyCategory(
        slug="memory_prompt_injection",
        title="Prompt-injection markers written into memory",
        owasp_amg_id="ASI06.1",
        description=(
            "An attacker gets an instruction-like payload persisted into the agent's memory "
            "(a 'rule', 'policy', or standing directive) so that a later, unrelated turn -- "
            "possibly a different session or a different user entirely -- re-reads it as if it "
            "were a legitimate system/developer instruction rather than untrusted past input."
        ),
        atlas_technique_ids=("AML.T0051",),
    ),
    "sensitive_data_leakage": TaxonomyCategory(
        slug="sensitive_data_leakage",
        title="Sensitive data leakage from memory",
        owasp_amg_id="ASI06.2",
        description=(
            "Content that should stay confined to one session, one user, or one internal channel "
            "(PII, credentials, internal notes, another user's data) is written to shared/durable "
            "memory and later surfaces unprompted or to an unauthorized principal."
        ),
    ),
    "protected_key_tampering": TaxonomyCategory(
        slug="protected_key_tampering",
        title="Protected-key / access-marker tampering",
        owasp_amg_id="ASI06.3",
        description=(
            "An attacker gets a security-relevant marker in memory -- an access level, a "
            "permission flag, an approval/consent record -- overwritten or fabricated, so the "
            "agent later treats the attacker (or anyone) as more privileged than they are."
        ),
    ),
    "memory_integrity_violation": TaxonomyCategory(
        slug="memory_integrity_violation",
        title="Memory integrity violation (silent overwrite)",
        owasp_amg_id="ASI06.4",
        description=(
            "A previously stored, legitimate fact is silently contradicted or overwritten by a "
            "later write with no provenance check, conflict flag, or trace of the change -- the "
            "agent has no way to tell the new value came from a less-trusted source."
        ),
    ),
    "bulk_injection_anomaly": TaxonomyCategory(
        slug="bulk_injection_anomaly",
        title="Bulk / oversized injection anomaly",
        owasp_amg_id="ASI06.5",
        description=(
            "An abnormally large or repetitive write is accepted into memory without any "
            "size/rate anomaly check, which both increases the odds of a payload surviving "
            "summarization and would, on a guarded target, itself be a detectable signal."
        ),
    ),
    "tool_output_instruction_injection": TaxonomyCategory(
        slug="tool_output_instruction_injection",
        title="Tool-result-borne instruction injection / unauthorized tool invocation",
        owasp_amg_id="ASI06.1",   # same underlying mechanism as memory_prompt_injection, different delivery channel
        description=(
            "The payload arrives via a tool's return value (a document, search result, API "
            "response) rather than a chat turn, and steers the agent's later tool selection, "
            "tool arguments, or an unauthorized action -- 'tool result stays data, not "
            "instructions' is the invariant under test."
        ),
        atlas_technique_ids=("AML.T0070",),
    ),
}

OWASP_AMG_CATEGORY_SLUGS: Tuple[str, ...] = tuple(OWASP_AMG_CATEGORIES)


def category(slug: str) -> TaxonomyCategory:
    try:
        return OWASP_AMG_CATEGORIES[slug]
    except KeyError as exc:
        raise KeyError(f"unknown owasp_amg_category {slug!r}; known: {sorted(OWASP_AMG_CATEGORY_SLUGS)}") from exc


def is_known_category(slug: str) -> bool:
    return slug in OWASP_AMG_CATEGORIES


# --------------------------------------------------------------------------- #
# Delivery / obfuscation techniques (orthogonal to the 6 memory-focused AMG
# categories above). A variant can carry both: AMG says *what* is being
# poisoned, this says *how* the payload is delivered or disguised.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TechniqueCategory:
    slug: str                    # 'obfuscation_encoding', 'many_shot', 'payload_splitting', ...
    title: str
    owasp_llm_id: str            # OWASP LLM Top-10 2025, usually 'LLM01' (Prompt Injection)
    atlas_technique_ids: Tuple[str, ...]   # e.g. ('AML.T0051.000',)
    description: str


ATTACK_TECHNIQUE_CATEGORIES: Dict[str, TechniqueCategory] = {
    "direct_instruction_override": TechniqueCategory(
        slug="direct_instruction_override",
        title="Direct instruction override",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="A blunt standing-rule / system-note ask that tries to replace the agent's instructions.",
    ),
    "authority_impersonation": TechniqueCategory(
        slug="authority_impersonation",
        title="Authority / compliance impersonation",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="The payload is framed as coming from an administrator, auditor, or other authority.",
    ),
    "obfuscation_encoding": TechniqueCategory(
        slug="obfuscation_encoding",
        title="Obfuscation / encoding",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051.000",),
        description="The instruction is wrapped in base64, rot13, hex, or unicode-escape to dodge keyword filters.",
    ),
    "payload_splitting": TechniqueCategory(
        slug="payload_splitting",
        title="Payload splitting",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="The payload is assembled from several individually-benign turns or fragments.",
    ),
    "many_shot": TechniqueCategory(
        slug="many_shot",
        title="Many-shot priming",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="A long fake dialogue that legitimizes a standing rule by example before asking for it.",
    ),
    "refusal_suppression": TechniqueCategory(
        slug="refusal_suppression",
        title="Refusal / disclaimer suppression",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="A standing rule that the agent must not refuse, hedge, or attach safety disclaimers.",
    ),
    "roleplay_persona": TechniqueCategory(
        slug="roleplay_persona",
        title="Roleplay / persona override",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="The ask is wrapped in an unrestricted persona or in-character roleplay frame.",
    ),
    "low_resource_language": TechniqueCategory(
        slug="low_resource_language",
        title="Low-resource language",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="The same payload delivered in a less-filtered language to bypass keyword/English-centric guards.",
    ),
    "tool_result_injection": TechniqueCategory(
        slug="tool_result_injection",
        title="Tool-result / indirect injection",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0070",),
        description="The payload arrives via a tool return value (search snippet, email, document) rather than a chat turn.",
    ),
    "context_ignore": TechniqueCategory(
        slug="context_ignore",
        title="Ignore-previous-instructions",
        owasp_llm_id="LLM01",
        atlas_technique_ids=("AML.T0051",),
        description="An explicit 'ignore previous instructions' / context-reset ask persisted into memory.",
    ),
}

ATTACK_TECHNIQUE_CATEGORY_SLUGS: Tuple[str, ...] = tuple(ATTACK_TECHNIQUE_CATEGORIES)


def technique_category(slug: str) -> TechniqueCategory:
    try:
        return ATTACK_TECHNIQUE_CATEGORIES[slug]
    except KeyError as exc:
        raise KeyError(
            f"unknown technique_category {slug!r}; known: {sorted(ATTACK_TECHNIQUE_CATEGORY_SLUGS)}"
        ) from exc


def is_known_technique(slug: str) -> bool:
    return slug in ATTACK_TECHNIQUE_CATEGORIES
