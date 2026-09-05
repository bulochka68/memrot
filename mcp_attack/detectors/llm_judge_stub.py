"""Phase-2 stub: an LLM judge asks an independent model whether the *injected
behavior* shows up (not just a literal token) -- needed once memory is
summarized/paraphrased and the literal canary no longer survives.

Not implemented in phase 1: no LLM client exists in this package yet, and no
attacker/judge API key or local endpoint has been configured. To build this:

1. A judge needs a ``base_url`` + ``model`` + ``api_key`` triple (hosted API
   such as gpt-4o-mini, or a local OpenAI-compatible endpoint such as Ollama
   serving qwen). None of these are supplied yet -- ask the user before
   wiring this up for real, per their own instruction.
2. The judge rubric comes from ``AttackVariant.rule_semantic`` (a short
   natural-language description of the behavior to look for), combined with
   the pre/post text.
3. On judge failure (timeout, malformed judgement, missing config), degrade
   to :class:`mcp_attack.detectors.literal.LiteralDetector` rather than
   raising -- an unavailable judge should never turn a run into ERROR.
"""
from __future__ import annotations

from typing import Optional

from ..models import DetectionChannel, DetectionResult
from .base import Detector


class LLMJudgeDetector(Detector):
    kind = "llm_judge"

    def __init__(self, *, base_url: Optional[str] = None, model: Optional[str] = None,
                 api_key_env: Optional[str] = None) -> None:
        raise NotImplementedError(
            "LLMJudgeDetector is a phase-2 stub: needs base_url/model/api_key_env for an attacker/judge "
            "LLM (hosted API or local Ollama-style OpenAI-compatible endpoint) plus a fallback-to-literal "
            "policy on judge failure. Not wired up yet -- see this module's docstring."
        )

    def detect(self, text: Optional[str], canary: str, channel: DetectionChannel) -> DetectionResult:
        raise NotImplementedError
