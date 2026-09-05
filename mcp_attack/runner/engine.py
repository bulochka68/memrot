"""The core, target-agnostic attack engine.

Implements the canary methodology's four-phase flow -- baseline -> inject ->
consolidate -> probe -- for ``cross-user``/``cross-session-same-user``
variants, and a simpler one-shot flow for ``single-turn`` control variants
(no persistent state involved, so ``INVALID`` is structurally impossible
there). The engine only calls :class:`~mcp_attack.adapters.base.TargetAdapter`
methods and never knows which concrete target is bound.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from ..adapters.base import AdapterCapabilities, TargetAdapter
from ..detectors.base import Detector
from ..detectors.ground_truth import GroundTruthDetector
from ..models import (AttackResult, AttackVariant, Channel, ChannelRole, DetectionChannel,
                      DetectionResult, RunReport, Verdict, default_run_id)
from ..tracer import JSONLTracer
from .verdict import decide_verdict


def _pick_channel(channels: List[Channel], role: str, principal_id: Optional[str]) -> Channel:
    candidates = [c for c in channels if c.role.value == role]
    if principal_id:
        for c in candidates:
            if c.principal.principal_id == principal_id:
                return c
        raise ValueError(f"no channel with role={role!r} and principal_id={principal_id!r} configured")
    if not candidates:
        raise ValueError(f"no channel with role={role!r} configured")
    return candidates[0]


def _safe_format(text: str, **kwargs) -> str:
    try:
        return text.format(**kwargs)
    except (KeyError, IndexError):
        return text


def _or_present(*detections: Optional[DetectionResult]) -> bool:
    return any(d.canary_present for d in detections if d is not None)


def run_variant(variant: AttackVariant, channels: List[Channel], adapter: TargetAdapter,
                detector: Detector, tracer: JSONLTracer, run_id: str) -> AttackResult:
    caps = adapter.capabilities()
    if variant.access_profile_required == "white_box" and caps.access_profile != "white_box":
        tracer.log(run_id=run_id, trace_id=variant.id, phase="skip",
                  text=f"required white_box, adapter is {caps.access_profile}")
        return AttackResult(
            variant_id=variant.id, verdict=Verdict.NOT_EVALUATED,
            rule_ids=list(variant.rule_ids), taxonomy=list(variant.taxonomy),
            owasp_amg_category=variant.owasp_amg_category, mutation_technique=variant.mutation_technique,
            framing=variant.framing, payload=variant.payload, layer=variant.layer,
            propagation=variant.propagation,
            limitations=[f"adapter access_profile={caps.access_profile} does not meet "
                        f"variant.access_profile_required=white_box"],
        )
    try:
        if variant.propagation == "single-turn":
            return _run_single_turn_control(variant, channels, adapter, detector, tracer, run_id)
        return _run_canary_flow(variant, channels, adapter, caps, detector, tracer, run_id)
    except Exception as exc:  # noqa: BLE001 -- an adapter/transport failure must surface as ERROR, never crash the matrix
        tracer.log(run_id=run_id, trace_id=variant.id, phase="error", error=f"{type(exc).__name__}: {exc}")
        return AttackResult(
            variant_id=variant.id, verdict=Verdict.ERROR, error=f"{type(exc).__name__}: {exc}",
            rule_ids=list(variant.rule_ids), taxonomy=list(variant.taxonomy),
            owasp_amg_category=variant.owasp_amg_category, mutation_technique=variant.mutation_technique,
            framing=variant.framing, payload=variant.payload, layer=variant.layer,
            propagation=variant.propagation,
        )


def _run_single_turn_control(variant: AttackVariant, channels: List[Channel], adapter: TargetAdapter,
                             detector: Detector, tracer: JSONLTracer, run_id: str) -> AttackResult:
    channel = _pick_channel(channels, variant.attacker_role, variant.attacker_principal)
    marker = variant.target_ref or variant.canary_template or ""

    session_id = adapter.new_session(channel.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=channel.principal.principal_id,
              phase="probe", channel_id=channel.channel_id, session_id=session_id,
              direction="request", text=variant.probe, canary=marker)
    response = adapter.send(channel.principal, session_id, variant.probe)
    text_det = detector.detect(response, marker, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=channel.principal.principal_id,
              phase="probe", channel_id=channel.channel_id, session_id=session_id,
              direction="response", text=response, canary=marker, canary_present=text_det.canary_present)

    gt_present = adapter.ground_truth_check(marker, target_ref=variant.target_ref)
    gt_det = GroundTruthDetector.wrap(gt_present)
    if gt_det is not None:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="ground_truth", direction="inspection",
                  canary=marker, canary_present=gt_det.canary_present)

    post_present = _or_present(text_det, gt_det)
    verdict = decide_verdict(False, post_present)   # INVALID is structurally impossible: no baseline phase
    tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=verdict.value)

    return AttackResult(
        variant_id=variant.id, verdict=verdict, post_detection=text_det, ground_truth_detection=gt_det,
        rule_ids=list(variant.rule_ids), taxonomy=list(variant.taxonomy),
        owasp_amg_category=variant.owasp_amg_category, mutation_technique=variant.mutation_technique,
        framing=variant.framing, payload=variant.payload, layer=variant.layer, propagation=variant.propagation,
        channels_used=[channel.channel_id], canary=marker,
    )


def _run_canary_flow(variant: AttackVariant, channels: List[Channel], adapter: TargetAdapter,
                     caps: AdapterCapabilities, detector: Detector, tracer: JSONLTracer,
                     run_id: str) -> AttackResult:
    attacker = _pick_channel(channels, variant.attacker_role, variant.attacker_principal)
    if variant.propagation == "cross-session-same-user":
        victim = attacker
    else:
        victim = _pick_channel(channels, variant.victim_role, variant.victim_principal)

    token = uuid.uuid4().hex[:10]
    canary = _safe_format(variant.canary_template, canary=f"{run_id[:6]}-{token}") if variant.canary_template else token
    channels_used = sorted({attacker.channel_id, victim.channel_id})

    # -- 0. baseline: negative control, fresh victim session -------------- #
    baseline_session = adapter.new_session(victim.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="baseline", channel_id=victim.channel_id, session_id=baseline_session,
              direction="request", text=variant.probe, canary=canary)
    baseline_response = adapter.send(victim.principal, baseline_session, variant.probe)
    baseline_text_det = detector.detect(baseline_response, canary, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="baseline", channel_id=victim.channel_id, session_id=baseline_session,
              direction="response", text=baseline_response, canary=canary,
              canary_present=baseline_text_det.canary_present)

    baseline_mem_det = None
    if caps.supports_inspect_memory:
        mem_text = adapter.inspect_memory(victim.principal)
        baseline_mem_det = detector.detect(mem_text, canary, DetectionChannel.MEMORY_INSPECTION)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
                  phase="baseline", direction="inspection", canary=canary,
                  canary_present=baseline_mem_det.canary_present, memory={"channel": "inspect_memory"})

    baseline_present = _or_present(baseline_text_det, baseline_mem_det)
    if baseline_present:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=Verdict.INVALID.value)
        return AttackResult(
            variant_id=variant.id, verdict=Verdict.INVALID, baseline_detection=baseline_text_det,
            rule_ids=list(variant.rule_ids), taxonomy=list(variant.taxonomy),
            owasp_amg_category=variant.owasp_amg_category, mutation_technique=variant.mutation_technique,
            framing=variant.framing, payload=variant.payload, layer=variant.layer, propagation=variant.propagation,
            channels_used=channels_used, canary=canary,
            limitations=["canary already present before this variant's own injection ran: "
                        "stale contamination from a previous run"],
        )

    # -- 1. inject ---------------------------------------------------------- #
    attack_session = adapter.new_session(attacker.principal)
    for turn in variant.inject_turns:
        rendered = _safe_format(turn, canary=canary)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=attacker.principal.principal_id,
                  phase="inject", channel_id=attacker.channel_id, session_id=attack_session,
                  direction="request", text=rendered, canary=canary)
        reply = adapter.send(attacker.principal, attack_session, rendered)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=attacker.principal.principal_id,
                  phase="inject", channel_id=attacker.channel_id, session_id=attack_session,
                  direction="response", text=reply, canary=canary)

    # -- 2. consolidate ------------------------------------------------------- #
    tracer.log(run_id=run_id, trace_id=variant.id, principal=attacker.principal.principal_id,
              phase="consolidate", channel_id=attacker.channel_id, session_id=attack_session)
    adapter.consolidate(attacker.principal, attack_session)

    # -- 3. probe: fresh victim session --------------------------------------- #
    probe_session = adapter.new_session(victim.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="probe", channel_id=victim.channel_id, session_id=probe_session,
              direction="request", text=variant.probe, canary=canary)
    probe_response = adapter.send(victim.principal, probe_session, variant.probe)
    post_text_det = detector.detect(probe_response, canary, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="probe", channel_id=victim.channel_id, session_id=probe_session,
              direction="response", text=probe_response, canary=canary,
              canary_present=post_text_det.canary_present)

    post_mem_det = None
    if caps.supports_inspect_memory:
        mem_text = adapter.inspect_memory(victim.principal)
        post_mem_det = detector.detect(mem_text, canary, DetectionChannel.MEMORY_INSPECTION)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
                  phase="memory_inspection", direction="inspection", canary=canary,
                  canary_present=post_mem_det.canary_present)

    gt_det = None
    if caps.supports_ground_truth:
        gt_present = adapter.ground_truth_check(canary, target_ref=variant.target_ref)
        gt_det = GroundTruthDetector.wrap(gt_present)
        if gt_det is not None:
            tracer.log(run_id=run_id, trace_id=variant.id, phase="ground_truth", direction="inspection",
                      canary=canary, canary_present=gt_det.canary_present)

    post_present = _or_present(post_text_det, post_mem_det, gt_det)
    verdict = decide_verdict(baseline_present, post_present)
    tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=verdict.value)

    return AttackResult(
        variant_id=variant.id, verdict=verdict, baseline_detection=baseline_text_det,
        post_detection=post_text_det, ground_truth_detection=gt_det,
        rule_ids=list(variant.rule_ids), taxonomy=list(variant.taxonomy),
        owasp_amg_category=variant.owasp_amg_category, mutation_technique=variant.mutation_technique,
        framing=variant.framing, payload=variant.payload, layer=variant.layer, propagation=variant.propagation,
        channels_used=channels_used, canary=canary,
    )


def run_matrix(variants: List[AttackVariant], channels: List[Channel], adapter: TargetAdapter,
               detector: Detector, tracer: JSONLTracer, run_id: Optional[str] = None,
               reset_between_variants: bool = False) -> RunReport:
    from ..reporting.aggregate import aggregate   # local import: avoids a reporting<->runner import cycle

    run_id = run_id or default_run_id()
    limitations: List[str] = []
    results: List[AttackResult] = []
    reset_note_added = False

    for variant in variants:
        if reset_between_variants:
            if not adapter.reset() and not reset_note_added:
                limitations.append(
                    "adapter does not support reset(); variants share target state across this run -- "
                    "the mandatory per-variant baseline phase is the cross-variant contamination safety net"
                )
                reset_note_added = True
        results.append(run_variant(variant, channels, adapter, detector, tracer, run_id))

    report = RunReport(run_id=run_id, target_id=adapter.kind, results=results, channels=list(channels),
                       limitations=limitations, trace_path=tracer.path)
    aggregate(report)
    return report
