"""Pluggable attack-variant generation.

Phase 1 ships exactly one working generator (:class:`StaticCatalogGenerator`)
-- canned, pre-written variants loaded from ``catalog/prompts/*/catalog.json``.
The other two are documented seams for phase 2, deliberately left as
``NotImplementedError`` stubs rather than half-built: a config can already
select ``generator.kind`` in anticipation of them (see ``config.py``), so
switching a run over later needs no core-engine change, only the generator.
"""
from __future__ import annotations

import abc
from typing import Iterable, List, Optional

from ..models import AttackVariant
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
    """Phase 2: takes seed variants and an attacker LLM, produces paraphrases
    / mutations, optionally iterating against detector feedback (a simple
    hill-climbing loop: keep mutations that flip CLEAN->CONFIRMED).

    Needs from the user before this can be built: an attacker-model
    ``base_url``/``model``/``api_key`` triple (their own hosted API key, e.g.
    gpt-4o-mini, or a local Ollama/vLLM OpenAI-compatible endpoint) -- ask
    before wiring this up."""
    kind = "llm_mutation"

    def __init__(self, seed_variants: Iterable[AttackVariant], *, base_url: Optional[str] = None,
                 model: Optional[str] = None, api_key_env: Optional[str] = None,
                 max_mutations_per_seed: int = 5) -> None:
        raise NotImplementedError(
            "LLMMutationGenerator is a phase-2 stub: needs an attacker-LLM base_url/model/api_key_env "
            "(hosted API key or local OpenAI-compatible endpoint) before it can generate real mutations."
        )

    def generate(self) -> List[AttackVariant]:
        raise NotImplementedError


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


_REGISTRY = {"static_catalog": StaticCatalogGenerator}


def build_generator(kind: str, **kwargs) -> AttackGenerator:
    cls = _REGISTRY.get(kind)
    if cls is None:
        raise ValueError(f"unknown or not-yet-implemented generator kind {kind!r}; available: {sorted(_REGISTRY)}")
    return cls(**kwargs)
