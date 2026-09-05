"""Pluggable attack-variant generation.

:class:`StaticCatalogGenerator` loads canned, pre-written variants from
``catalog/prompts/*/catalog.json``. :class:`LLMMutationGenerator` takes those
same seed variants and, for each requested mutation technique (see
``mcp_attack/mutation/techniques.py``), produces a reworded variant tagged
with which technique produced it -- so a run's statistics can break out ASR
per mutation technique, not just per seed. ``ImportedBankGenerator`` remains
a documented seam: importing whole probe families from garak/llamator/
promptfoo needs a deliberate per-probe decision about which ones fit this
harness's canary methodology, not a blanket bulk import.
"""
from __future__ import annotations

import abc
from typing import Iterable, List, Optional

from ..models import AttackVariant
from ..mutation.llm_client import LLMClient, LLMClientConfig
from ..mutation.techniques import build_technique
from .loader import load_catalog


class AttackGenerator(abc.ABC):
    kind: str = "abstract"

    @abc.abstractmethod
    def generate(self) -> List[AttackVariant]:
        raise NotImplementedError


class StaticCatalogGenerator(AttackGenerator):
    """Loads pre-written variants from one or more catalog.json files/dirs."""
    kind = "static_catalog"

    def __init__(self, catalog_paths: Iterable[str], strict: bool = True) -> None:
        self.catalog_paths = list(catalog_paths)
        self.strict = strict

    def generate(self) -> List[AttackVariant]:
        return load_catalog(self.catalog_paths, strict=self.strict)


class LLMMutationGenerator(AttackGenerator):
    """Takes seed variants and, for each ``techniques`` slug, produces one
    mutated variant per seed via ``mcp_attack.mutation.techniques``. Cheap
    techniques (``prefix_injection``, ``base64_obfuscation``,
    ``persona_override``) need no LLM; the rest (``paraphrase``,
    ``roleplay_framing``, ``translation``, ``escalation_rewrite``) do, and
    ``base_url``/``model`` are then required.

    A single mutation failure (LLM call error, a technique that doesn't
    apply to a given seed's shape) is skipped rather than aborting the whole
    generation -- the seed and every other technique/seed combination still
    run. ``keep_seeds`` controls whether the unmutated originals are also
    included in the output (default: yes, so a mutation run's ASR-by-axis
    breakdown still has an unmutated baseline to compare against)."""
    kind = "llm_mutation"

    def __init__(self, seed_variants: Iterable[AttackVariant], *, techniques: Iterable[str] = ("prefix_injection",),
                 base_url: Optional[str] = None, model: Optional[str] = None,
                 api_key_env: Optional[str] = None, max_mutations_per_seed: Optional[int] = None,
                 keep_seeds: bool = True) -> None:
        self.seed_variants = list(seed_variants)
        self.technique_slugs = list(techniques)
        self.techniques = [build_technique(slug) for slug in self.technique_slugs]
        self.max_mutations_per_seed = max_mutations_per_seed
        self.keep_seeds = keep_seeds

        self.llm: Optional[LLMClient] = None
        if any(t.requires_llm for t in self.techniques):
            if not base_url or not model:
                needing = [t.slug for t in self.techniques if t.requires_llm]
                raise ValueError(f"techniques {needing} require an LLM: base_url and model are required")
            self.llm = LLMClient(LLMClientConfig(base_url=base_url, model=model, api_key_env=api_key_env))

    def generate(self) -> List[AttackVariant]:
        out: List[AttackVariant] = list(self.seed_variants) if self.keep_seeds else []
        for seed in self.seed_variants:
            produced = 0
            for technique in self.techniques:
                if self.max_mutations_per_seed is not None and produced >= self.max_mutations_per_seed:
                    break
                try:
                    out.append(technique.mutate(seed, llm=self.llm))
                    produced += 1
                except Exception:
                    continue   # a single technique/seed mismatch or LLM failure must not abort the whole run
        return out


class ImportedBankGenerator(AttackGenerator):
    """Phase 2: converts prompts from an external red-team prompt bank
    (garak probes, llamator attacks, promptfoo redteam plugins) into
    :class:`AttackVariant` objects.

    Needs from the user: which specific probes/plugins to port first (garak
    has dozens of unrelated probe families; llamator/promptfoo similarly) --
    a blanket "import everything" would mostly produce single-turn,
    non-memory-aware variants that don't fit this harness's canary
    methodology well, so pick converters deliberately rather than in bulk."""
    kind = "imported_bank"

    def __init__(self, bank: str, source_path: str) -> None:
        raise NotImplementedError(
            f"ImportedBankGenerator is a phase-2 stub: no converter for bank={bank!r} exists yet -- "
            "decide which specific probes/plugins to port before building this."
        )

    def generate(self) -> List[AttackVariant]:
        raise NotImplementedError


_REGISTRY = {"static_catalog": StaticCatalogGenerator, "llm_mutation": LLMMutationGenerator}


def build_generator(kind: str, **kwargs) -> AttackGenerator:
    cls = _REGISTRY.get(kind)
    if cls is None:
        raise ValueError(f"unknown or not-yet-implemented generator kind {kind!r}; available: {sorted(_REGISTRY)}")
    return cls(**kwargs)
