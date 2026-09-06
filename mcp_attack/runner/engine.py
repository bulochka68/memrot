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
                      DetectionResult, RunReport, Verdict, default_run_id, path_state_for)
from ..tracer import JSONLTracer
from .verdict import decide_verdict


def _tagged(variant: AttackVariant, **kwargs) -> AttackResult:
    """Copy axis/taxonomy tags off the variant onto a result so a new field
    on AttackVariant cannot be silently dropped from AttackResult."""
    base = dict(
        variant_id=variant.id,
        rule_ids=list(variant.rule_ids),
        taxonomy=list(variant.taxonomy),
        owasp_amg_category=variant.owasp_amg_category,
        technique_category=variant.technique_category,
        mutation_technique=variant.mutation_technique,
        delivery_channel=variant.delivery_channel,
        threat_model=variant.threat_model,
        source=variant.source,
        framing=variant.framing,
        payload=variant.payload,
        layer=variant.layer,
        propagation=variant.propagation,
    )
    base.update(kwargs)
    result = AttackResult(**base)
    if not result.path_state:
        result.path_state = path_state_for(result.verdict, result.propagation)
    return result


def _tool_vector(variant: AttackVariant) -> str:
    stage = variant.tool_stage or {}
    return stage.get("vector") or "web_search"


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
        return _tagged(variant, verdict=Verdict.NOT_EVALUATED,
                       limitations=[f"adapter access_profile={caps.access_profile} does not meet "
                                    f"variant.access_profile_required=white_box"])
    if variant.delivery_channel == "tool_result" and not caps.supports_tool_staging:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="skip",
                  text="requires tool-result staging, adapter lacks supports_tool_staging")
        return _tagged(variant, verdict=Verdict.NOT_EVALUATED,
                       limitations=["adapter does not support stage_tool_response(); this delivery_channel='tool_result' "
                                    "variant cannot be evaluated black-box against this target"])
    if variant.delivery_channel == "tool_result":
        vector = _tool_vector(variant)
        supported = list(caps.supported_tool_vectors or [])
        if vector not in supported:
            tracer.log(run_id=run_id, trace_id=variant.id, phase="skip",
                      text=f"tool vector {vector!r} not in adapter supported_tool_vectors={supported}")
            return _tagged(variant, verdict=Verdict.NOT_EVALUATED,
                           limitations=[f"adapter does not support tool vector {vector!r} "
                                        f"(supported: {supported or 'none'}); not evaluated rather than a false CLEAN"])
    if variant.delivery_channel == "document_ingestion" and not caps.supports_document_ingestion:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="skip",
                  text="requires document ingestion, adapter lacks supports_document_ingestion")
        return _tagged(variant, verdict=Verdict.NOT_EVALUATED,
                       limitations=["adapter does not support ingest_document(); this "
                                    "delivery_channel='document_ingestion' variant cannot be evaluated against this target"])
    try:
        if variant.delivery_channel == "tool_result":
            return _run_tool_injection_flow(variant, channels, adapter, caps, detector, tracer, run_id)
        if variant.delivery_channel == "document_ingestion":
            return _run_document_ingestion_flow(variant, channels, adapter, caps, detector, tracer, run_id)
        if variant.propagation == "single-turn":
            return _run_single_turn_control(variant, channels, adapter, detector, tracer, run_id)
        return _run_canary_flow(variant, channels, adapter, caps, detector, tracer, run_id)
    except Exception as exc:  # noqa: BLE001 -- an adapter/transport failure must surface as ERROR, never crash the matrix
        tracer.log(run_id=run_id, trace_id=variant.id, phase="error", error=f"{type(exc).__name__}: {exc}")
        return _tagged(variant, verdict=Verdict.ERROR, error=f"{type(exc).__name__}: {exc}")


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

    return _tagged(variant, verdict=verdict, post_detection=text_det, ground_truth_detection=gt_det,
                   channels_used=[channel.channel_id], canary=marker)


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
        return _tagged(variant, verdict=Verdict.INVALID, baseline_detection=baseline_text_det,
                       channels_used=channels_used, canary=canary,
                       limitations=["canary already present before this variant's own injection ran: "
                                    "stale contamination from a previous run"])

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

    return _tagged(variant, verdict=verdict, baseline_detection=baseline_text_det,
                   post_detection=post_text_det, ground_truth_detection=gt_det,
                   channels_used=channels_used, canary=canary)


def _run_tool_injection_flow(variant: AttackVariant, channels: List[Channel], adapter: TargetAdapter,
                             caps: AdapterCapabilities, detector: Detector, tracer: JSONLTracer,
                             run_id: str) -> AttackResult:
    """Indirect prompt injection delivered via a tool result (e.g. a poisoned
    web-search snippet) rather than a direct chat turn.

    Note the victim, not an "attacker" principal, sends ``trigger_message``:
    the attacker's only real-world capability is planting content somewhere
    a tool will surface it (an indexed web page, a staged snippet here); it
    is the victim's own ordinary query that makes the target invoke the
    poisoned tool. ``laundering_detected`` is a diagnostic signal, not the
    verdict: many targets only ever persist an assistant's own visible reply
    into memory (no raw "tool" role in their transcript), so the injected
    content must first get echoed/affirmed there before it has any chance of
    surviving into memory -- this records whether that happened without
    changing the canary verdict truth table.
    """
    victim = _pick_channel(channels, variant.victim_role, variant.victim_principal)
    probe_channel = (_pick_channel(channels, variant.victim_role, variant.second_client_principal)
                    if variant.second_client_principal else victim)

    token = uuid.uuid4().hex[:10]
    canary = _safe_format(variant.canary_template, canary=f"{run_id[:6]}-{token}") if variant.canary_template else token
    channels_used = sorted({victim.channel_id, probe_channel.channel_id})

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

    baseline_present = baseline_text_det.canary_present
    if baseline_present:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=Verdict.INVALID.value)
        return _tagged(variant, verdict=Verdict.INVALID, baseline_detection=baseline_text_det,
                       channels_used=channels_used, canary=canary,
                       limitations=["canary already present before this variant's own injection ran: "
                                    "stale contamination from a previous run"])

    # -- 1. stage the tool result, then let the victim trigger it naturally -- #
    tool_name = variant.tool_stage["tool_name"]
    staged_content = _safe_format(variant.tool_stage["content_template"], canary=canary)
    tracer.log(run_id=run_id, trace_id=variant.id, phase="stage_tool", direction="request",
              text=f"tool={tool_name}", canary=canary, tool={"tool_name": tool_name})
    adapter.stage_tool_response(tool_name, staged_content, vector=_tool_vector(variant))

    trigger_session = adapter.new_session(victim.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="trigger", channel_id=victim.channel_id, session_id=trigger_session,
              direction="request", text=variant.trigger_message, canary=canary)
    trigger_reply = adapter.send(victim.principal, trigger_session, variant.trigger_message)
    laundering_detected = detector.detect(trigger_reply, canary, DetectionChannel.RESPONSE_TEXT).canary_present
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="trigger", channel_id=victim.channel_id, session_id=trigger_session,
              direction="response", text=trigger_reply, canary=canary, canary_present=laundering_detected)

    # -- 2. consolidate ------------------------------------------------------- #
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="consolidate", channel_id=victim.channel_id, session_id=trigger_session)
    adapter.consolidate(victim.principal, trigger_session)

    # -- 3. probe: fresh session, possibly a second client -------------------- #
    probe_session = adapter.new_session(probe_channel.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="probe", channel_id=probe_channel.channel_id, session_id=probe_session,
              direction="request", text=variant.probe, canary=canary)
    probe_response = adapter.send(probe_channel.principal, probe_session, variant.probe)
    post_text_det = detector.detect(probe_response, canary, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="probe", channel_id=probe_channel.channel_id, session_id=probe_session,
              direction="response", text=probe_response, canary=canary,
              canary_present=post_text_det.canary_present)

    post_mem_det = None
    if caps.supports_inspect_memory:
        mem_text = adapter.inspect_memory(probe_channel.principal)
        post_mem_det = detector.detect(mem_text, canary, DetectionChannel.MEMORY_INSPECTION)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
                  phase="memory_inspection", direction="inspection", canary=canary,
                  canary_present=post_mem_det.canary_present)

    post_present = _or_present(post_text_det, post_mem_det)
    verdict = decide_verdict(baseline_present, post_present)
    tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=verdict.value,
              text=f"laundering_detected={laundering_detected}")

    return _tagged(variant, verdict=verdict, baseline_detection=baseline_text_det,
                   post_detection=post_text_det, laundering_detected=laundering_detected,
                   channels_used=channels_used, canary=canary)


def _run_document_ingestion_flow(variant: AttackVariant, channels: List[Channel], adapter: TargetAdapter,
                                 caps: AdapterCapabilities, detector: Detector, tracer: JSONLTracer,
                                 run_id: str) -> AttackResult:
    """RAG-like delivery: the victim submits a poisoned document/attachment,
    the target consolidates, then a fresh session is probed for the canary."""
    victim = _pick_channel(channels, variant.victim_role, variant.victim_principal)
    if variant.second_client_principal:
        probe_channel = _pick_channel(channels, variant.victim_role, variant.second_client_principal)
    elif variant.propagation == "cross-user":
        try:
            probe_channel = _pick_channel(channels, variant.attacker_role, variant.attacker_principal)
        except ValueError:
            probe_channel = victim
    else:
        probe_channel = victim

    token = uuid.uuid4().hex[:10]
    canary = _safe_format(variant.canary_template, canary=f"{run_id[:6]}-{token}") if variant.canary_template else token
    channels_used = sorted({victim.channel_id, probe_channel.channel_id})

    baseline_session = adapter.new_session(probe_channel.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="baseline", channel_id=probe_channel.channel_id, session_id=baseline_session,
              direction="request", text=variant.probe, canary=canary)
    baseline_response = adapter.send(probe_channel.principal, baseline_session, variant.probe)
    baseline_text_det = detector.detect(baseline_response, canary, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="baseline", channel_id=probe_channel.channel_id, session_id=baseline_session,
              direction="response", text=baseline_response, canary=canary,
              canary_present=baseline_text_det.canary_present)

    if baseline_text_det.canary_present:
        tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=Verdict.INVALID.value)
        return _tagged(variant, verdict=Verdict.INVALID, baseline_detection=baseline_text_det,
                       channels_used=channels_used, canary=canary,
                       limitations=["canary already present before this variant's own injection ran: "
                                    "stale contamination from a previous run"])

    document_text = "\n\n".join(_safe_format(turn, canary=canary) for turn in variant.inject_turns)
    ingest_session = adapter.new_session(victim.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="ingest", channel_id=victim.channel_id, session_id=ingest_session,
              direction="request", text=document_text, canary=canary)
    ingest_reply = adapter.ingest_document(victim.principal, ingest_session, document_text)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="ingest", channel_id=victim.channel_id, session_id=ingest_session,
              direction="response", text=ingest_reply, canary=canary)

    tracer.log(run_id=run_id, trace_id=variant.id, principal=victim.principal.principal_id,
              phase="consolidate", channel_id=victim.channel_id, session_id=ingest_session)
    adapter.consolidate(victim.principal, ingest_session)

    probe_session = adapter.new_session(probe_channel.principal)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="probe", channel_id=probe_channel.channel_id, session_id=probe_session,
              direction="request", text=variant.probe, canary=canary)
    probe_response = adapter.send(probe_channel.principal, probe_session, variant.probe)
    post_text_det = detector.detect(probe_response, canary, DetectionChannel.RESPONSE_TEXT)
    tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
              phase="probe", channel_id=probe_channel.channel_id, session_id=probe_session,
              direction="response", text=probe_response, canary=canary,
              canary_present=post_text_det.canary_present)

    post_mem_det = None
    if caps.supports_inspect_memory:
        mem_text = adapter.inspect_memory(probe_channel.principal)
        post_mem_det = detector.detect(mem_text, canary, DetectionChannel.MEMORY_INSPECTION)
        tracer.log(run_id=run_id, trace_id=variant.id, principal=probe_channel.principal.principal_id,
                  phase="memory_inspection", direction="inspection", canary=canary,
                  canary_present=post_mem_det.canary_present)

    post_present = _or_present(post_text_det, post_mem_det)
    verdict = decide_verdict(False, post_present)
    tracer.log(run_id=run_id, trace_id=variant.id, phase="verdict", verdict=verdict.value)
    return _tagged(variant, verdict=verdict, baseline_detection=baseline_text_det,
                   post_detection=post_text_det, channels_used=channels_used, canary=canary)


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
