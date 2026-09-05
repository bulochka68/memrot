"""INFRA-01 … INFRA-03: storage rights, network boundary, validation isolation (TZ §9)."""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (Applicability, ClaimStatus, Confidence, ControlOutcome, Method, RemediationPriority,
                      RunMode, Severity, SourceType)
from .base import Rule, RuleContext, RuleEvaluation, not_evaluated, status_from, worst


def _infra_applicable(ctx: RuleContext):
    if ctx.doc.deployment or ctx.flows("store_access") or ctx.policy.get("service_rights"):
        return Applicability.APPLICABLE, ""
    return Applicability.UNKNOWN, "no deployment snapshot or store-access facts"


def _infra01(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.POLICY_INSPECTION)
    outcomes: List[ControlOutcome] = []
    expected = ctx.policy.get("service_rights") or {}
    for acc in ctx.flows("store_access"):
        st = status_from([acc])
        if acc.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        comp, store = acc.get("from", ""), acc.get("to", "")
        rights = set(acc.get("rights") or [])
        allowed = set((expected.get(comp) or {}).get(store) or [])
        c = ctx.claim(f"CL-INFRA-01-{acc.get('id')}", acc.get("statement") or f"{comp} accesses {store} with {sorted(rights)}",
                      st, evidence_refs=acc.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[comp, store], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["rights are read from application code / config; DB-level privileges of the running store not queried"])
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif comp in expected and rights - allowed:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("EXCESSIVE_STORE_RIGHTS", f"{comp} holds rights on {store} beyond policy",
                              f"observed {sorted(rights)}, policy allows {sorted(allowed) or 'none'}.", status=st, severity=Severity.HIGH,
                              component_refs=[comp, store], claim_refs=[c.claim_id], evidence_refs=acc.get("evidence_refs") or [],
                              priority=RemediationPriority.P0, scope={"flow": acc.get("id")},
                              remediation="grant per-service store credentials with least privilege; keep shared-policy publication on a separate principal",
                              closure_criterion="service rights on memory stores match policy; publication is a separate credential")
            ev.finding_refs.append(fnd.finding_id)
        elif comp in expected:
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{comp}: no expected rights in policy for {store}")
    for name, svc in (ctx.doc.deployment.get("services") or {}).items():
        sa = svc.get("storage_auth")
        if sa and sa.get("auth") is None:
            ev.limitations.append(f"{name}: {sa.get('basis')}")
            c = ctx.claim(f"CL-INFRA-01-auth-{name}", f"{name}: authentication not shown in the deployment configuration",
                          ClaimStatus.STATIC_SUPPORTED, evidence_refs=[svc.get("evidence_ref")] if svc.get("evidence_ref") else [],
                          confidence=Confidence.MEDIUM, source_type=SourceType.DEPLOYMENT_SNAPSHOT, method=Method.PARSING,
                          limitations=["absence in this file is not proof of absence in the running deployment"])
            ev.claim_refs.append(c.claim_id)
            outcomes.append(ControlOutcome.INCONCLUSIVE)
    if not outcomes:
        return not_evaluated("no store-access facts, service-rights policy or storage services")
    ev.outcome = worst(outcomes)
    return ev


def _infra02(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.PARSING)
    outcomes: List[ControlOutcome] = []
    net_policy = ctx.policy.get("network") or {}
    forbid = net_policy.get("storage_publication") == "forbidden"
    for name, svc in (ctx.doc.deployment.get("services") or {}).items():
        if not svc.get("storage_kind"):
            continue
        published = svc.get("host_published") or []
        if not published:
            outcomes.append(ControlOutcome.PASS)
            continue
        loop = svc.get("loopback_only")
        c = ctx.claim(f"CL-INFRA-02-{name}", f"{name} ({svc['storage_kind']}) publishes port(s) {[p['published'] for p in published]} on the host"
                      + (" (loopback only)" if loop else ""),
                      ClaimStatus.STATIC_SUPPORTED, evidence_refs=[svc.get("evidence_ref")] if svc.get("evidence_ref") else [],
                      confidence=Confidence.HIGH, component_refs=[name], source_type=SourceType.DEPLOYMENT_SNAPSHOT, method=Method.PARSING,
                      limitations=["bind/publication only; reachability from a concrete external zone not observed"])
        ev.claim_refs.append(c.claim_id)
        ev.component_refs.append(name)
        if forbid and not loop:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("STORAGE_PUBLISHED_ON_HOST", f"{name} storage port published on the host",
                              c.statement + "; policy forbids storage publication.", status=ClaimStatus.STATIC_SUPPORTED,
                              severity=Severity.HIGH, component_refs=[name], claim_refs=[c.claim_id], evidence_refs=c.evidence_refs,
                              priority=RemediationPriority.P0,
                              potential_effect="direct access to memory/data stores from the host network zone; combined with missing auth, full read/write",
                              remediation="remove host publication, isolate storage networks, enable authentication and least-privilege service users",
                              closure_criterion="storage ports are not published; reachability from external zones is refused (observed per zone)",
                              limitations=["reachability from specific external zones not established"])
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{name}: publication observed; policy expectation {'absent' if not forbid else 'loopback allowed'}")
    if not outcomes:
        return not_evaluated("no deployment snapshot with storage services")
    ev.outcome = worst(outcomes)
    ev.interpretation = "bind, publication, routing and filtering are separate facts; only publication is observed here"
    return ev


def _infra03(ctx: RuleContext) -> RuleEvaluation:
    if ctx.doc.mode != RunMode.CONTROLLED_VALIDATION:
        return not_evaluated("no controlled validation was run in this mode")
    iso = ctx.doc.meta.get("isolation") or {}
    ev = RuleEvaluation(outcome=ControlOutcome.INCONCLUSIVE, method=Method.OBSERVATION)
    refs = [r for r in iso.get("evidence_refs") or [] if ctx.store.has(r)]
    c = ctx.claim("CL-INFRA-03-isolation",
                  f"isolation declared by flag/env={iso.get('declared')}; technical evidence: {iso.get('technical') or 'none'}",
                  ClaimStatus.STATIC_SUPPORTED if refs else ClaimStatus.HYPOTHESIS, evidence_refs=refs,
                  confidence=Confidence.MEDIUM if refs else Confidence.LOW,
                  limitations=["the sandbox flag and environment marker confirm intent, not OS/network/remote isolation"])
    ev.claim_refs.append(c.claim_id)
    if iso.get("technical", {}).get("attested"):
        ev.outcome = ControlOutcome.PASS
        ev.interpretation = "fixture attests technical isolation (data, network, permissions)"
    else:
        ev.limitations.append("no technical isolation attestation from the fixture; the local guard cannot prove isolation of a remote target")
    return ev


RULES: List[Rule] = [
    Rule("INFRA-01", "2.0.0", "Ограниченный доступ к памяти",
         "Доступ к хранилищу имеют нужные сервисы с минимальными правами; публикация общей политики выделена отдельно.",
         "Доступ к хранилищу имеют нужные сервисы с минимальными правами; публикация общей политики выделена отдельно",
         "infrastructure", [["source_snapshot", "policy_snapshot"], ["deployment"]],
         [Method.POLICY_INSPECTION, Method.STATIC_ANALYSIS, Method.PARSING],
         "service rights on memory stores are minimal and publication is separated", _infra01, _infra_applicable,
         remediation_criterion="service rights match policy; publication is a separate credential", default_priority=RemediationPriority.P0),
    Rule("INFRA-02", "2.0.0", "Наблюдаемая сетевая граница",
         "Отдельно описаны bind, публикация порта, маршрутизация и фильтрация; доступность подтверждается для конкретной зоны.",
         "Отдельно описаны bind, публикация порта, маршрутизация и фильтрация; доступность подтверждается для конкретной зоны",
         "infrastructure", [["deployment"]], [Method.PARSING, Method.OBSERVATION],
         "storage ports are not published beyond the intended zone", _infra02, _infra_applicable,
         known_false_positives=["a published port is not automatically reachable from the internet"],
         remediation_criterion="storage ports are not published; reachability is refused per zone", default_priority=RemediationPriority.P0),
    Rule("INFRA-03", "2.0.0", "Изоляция проверочного окружения",
         "Проверки используют изолированные данные и ограниченные полномочия; флаг в конфиге не считается обеспечением изоляции.",
         "Проверки используют изолированные данные и ограниченные полномочия; флаг в конфиге не считается обеспечением изоляции",
         "infrastructure", [["control_fixtures"]], [Method.OBSERVATION],
         "controlled validation runs on synthetic data with technical isolation attested by the fixture", _infra03,
         lambda ctx: (Applicability.APPLICABLE, "") if ctx.doc.mode == RunMode.CONTROLLED_VALIDATION else (Applicability.NOT_APPLICABLE, "no controlled validation in this mode"),
         remediation_criterion="fixture attests data, network and permission isolation", default_priority=RemediationPriority.P1),
]
