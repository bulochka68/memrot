"""TOOL-01 … TOOL-05 and EGRESS-01 … EGRESS-02 (TZ §10).

Definition text signals never prove compromise; a suspicious description does
not show that an ordinary user can change the server; receiving untrusted
content does not show it was stored; retelling does not make it trusted.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (Applicability, ClaimStatus, Confidence, ControlOutcome, Method, PathState,
                      RemediationPriority, RunMode, Severity, SourceType)
from .base import Rule, RuleContext, RuleEvaluation, not_evaluated, status_from, worst

_MCP_SEC = {"name": "MCP specification, Security and Trust & Safety", "url": "https://modelcontextprotocol.io/specification/2025-11-25",
            "note": "annotations describe behaviour but do not enforce it"}


def _tools_applicable(ctx: RuleContext):
    if ctx.doc.all_tools() or any(d.get("status") != "unknown" for d in ctx.facts.get("tool_declarations") or []):
        return Applicability.APPLICABLE, ""
    return Applicability.UNKNOWN, "no tool definitions in inventory or source"


def _tool01(ctx: RuleContext) -> RuleEvaluation:
    drift = ctx.doc.drift
    if not drift:
        return not_evaluated("no approved baseline was supplied (policy.tool_approval or --baseline)", ["baseline"])
    if drift.get("compatibility", {}).get("comparable") is False:
        return RuleEvaluation(outcome=ControlOutcome.INCONCLUSIVE, method=Method.PARSING,
                              interpretation="baseline not comparable: " + "; ".join(drift["compatibility"].get("reasons", [])),
                              limitations=drift["compatibility"].get("reasons", []))
    changes = [c for c in drift.get("changes") or [] if c.get("kind") in ("definition_changed", "added", "removed")]
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.PARSING,
                        evidence_refs=[drift.get("evidence_ref")] if drift.get("evidence_ref") else [])
    if not changes:
        ev.interpretation = "all definitions match the approved baseline"
        return ev
    unapproved = [c for c in changes if c.get("approval_state") != "approved"]
    c = ctx.claim("CL-TOOL-01-drift", f"{len(changes)} definition change(s) vs baseline; {len(unapproved)} not approved",
                  ClaimStatus.STATIC_SUPPORTED, evidence_refs=ev.evidence_refs, confidence=Confidence.HIGH,
                  source_type=SourceType.BASELINE, method=Method.PARSING,
                  limitations=["drift is a state, not proof of malicious intent or of impact"])
    ev.claim_refs.append(c.claim_id)
    if unapproved:
        ev.outcome = ControlOutcome.FAIL
        fnd = ctx.finding("DEFINITION_DRIFT_UNAPPROVED", "Tool definitions changed without approval",
                          "; ".join(f"{c.get('key')}: {c.get('kind')} ({c.get('approval_state')})" for c in unapproved[:10]),
                          status=ClaimStatus.STATIC_SUPPORTED, severity=Severity.HIGH, claim_refs=[c.claim_id],
                          evidence_refs=ev.evidence_refs, priority=RemediationPriority.P1,
                          potential_effect="a definition changed after approval may steer the model (rug pull) - not established by the change alone",
                          remediation="review and approve or reject the changed definitions; pin approved versions",
                          closure_criterion="every definition matches an approved baseline entry for this server identity/version",
                          limitations=["malice and impact require separate evidence"])
        ev.finding_refs.append(fnd.finding_id)
    return ev


def _tool02(ctx: RuleContext) -> RuleEvaluation:
    rec = ctx.doc.inventory_reconciliation
    mismatches = [r for r in rec if r.get("kind") == "contract_mismatch"]
    comparable = [r for r in rec if r.get("kind") in ("contract_mismatch", "contract_match")]
    if not comparable:
        return not_evaluated("only one definition source per tool; contracts cannot be compared", ["source_snapshot or live inventory"])
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS)
    for m in mismatches:
        refs = [r for r in m.get("evidence_refs") or [] if ctx.store.has(r)]
        c = ctx.claim(f"CL-TOOL-02-{m.get('tool')}", f"{m.get('tool')}: {m.get('detail')}", ClaimStatus.STATIC_SUPPORTED if refs else ClaimStatus.HYPOTHESIS,
                      evidence_refs=refs, confidence=Confidence.HIGH if refs else Confidence.MEDIUM,
                      source_type=SourceType.DEFINITION, method=Method.STATIC_ANALYSIS)
        ev.claim_refs.append(c.claim_id)
        fnd = ctx.finding("CONTRACT_MISMATCH", f"Operation contract mismatch: {m.get('tool')}", m.get("detail", ""),
                          status=c.claim_status, severity=Severity.MEDIUM, claim_refs=[c.claim_id], evidence_refs=refs,
                          server=m.get("server"), tool=m.get("tool_name"), priority=RemediationPriority.P1,
                          potential_effect="a check written against the stale schema fails on arguments before reaching the control under test",
                          remediation="align the configured/agreed schema with the build; version the contract",
                          closure_criterion="configured, source-defined and live schemas agree for the tool (names, required, types)",
                          evidence={"sources": m.get("sources"), "differences": m.get("differences")})
        ev.finding_refs.append(fnd.finding_id)
        ev.outcome = ControlOutcome.FAIL
    ev.interpretation = f"{len(comparable) - len(mismatches)} consistent, {len(mismatches)} mismatched contract(s)"
    return ev


def _tool03(ctx: RuleContext) -> RuleEvaluation:
    routing = ctx.profile.get("tool_routing") or {}
    ns = routing.get("namespace", "unknown")
    collisions = ctx.doc.collisions
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS,
                        interpretation=f"router namespace: {ns}; {len(collisions)} name collision(s)")
    if not collisions:
        if ns == "unknown" and len(ctx.doc.servers) > 1:
            ev.limitations.append("router namespace unknown; no collisions found in the current inventory")
        return ev
    refs = [f.evidence_refs[0] for f in ctx.doc.findings if f.code in ("TOOL_NAME_COLLISION", "TOOL_NAME_NEAR_COLLISION") and f.evidence_refs]
    c = ctx.claim("CL-TOOL-03-collisions", f"{len(collisions)} colliding tool name(s) across servers with router namespace {ns}",
                  ClaimStatus.STATIC_SUPPORTED if refs else ClaimStatus.HYPOTHESIS, evidence_refs=refs, confidence=Confidence.HIGH,
                  source_type=SourceType.DEFINITION, method=Method.STATIC_ANALYSIS,
                  limitations=["which definition the real router selects is not observed"])
    ev.claim_refs.append(c.claim_id)
    if ns in ("qualified", "namespaced"):
        ev.interpretation += "; qualified names resolve the ambiguity - collision is a signal only"
        return ev
    ev.outcome = ControlOutcome.FAIL if ns == "flat" else ControlOutcome.INCONCLUSIVE
    fnd = ctx.finding("AMBIGUOUS_TOOL_RESOLUTION", "Tool names collide under a flat / unknown router namespace",
                      f"collisions: {[c_.get('tool') for c_ in collisions]}; router namespace {ns}.",
                      status=c.claim_status if ns == "flat" else ClaimStatus.HYPOTHESIS,
                      severity=Severity.HIGH, potential_severity=Severity.HIGH, claim_refs=[c.claim_id], evidence_refs=refs,
                      priority=RemediationPriority.P1,
                      potential_effect="the model or the router may pick the wrong server's definition (shadowing precondition)",
                      remediation="qualify tool names per server in the router; reject duplicate registrations",
                      closure_criterion="router resolves qualified names; duplicate names are refused or namespaced",
                      limitations=["substitution is not declared without observing the router"])
    ev.finding_refs.append(fnd.finding_id)
    return ev


def _tool04(ctx: RuleContext) -> RuleEvaluation:
    chains = ctx.chain_state("TOOL-04")
    if not chains:
        return not_evaluated("no chain from tool results to policy/publication declared in the profile", ["profile.chains"])
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for ch in chains:
        state = PathState(ch.get("state", "unknown"))
        refs = [b for b in ch.get("basis") or [] if ctx.store.has(b)]
        if state in (PathState.STATIC_PATH_SUPPORTED, PathState.RUNTIME_PATH_OBSERVED, PathState.CONTROL_VIOLATION_OBSERVED):
            st = ClaimStatus.RUNTIME_SUPPORTED if state != PathState.STATIC_PATH_SUPPORTED and refs else ClaimStatus.STATIC_SUPPORTED
            c = ctx.claim(f"CL-TOOL-04-{ch.get('chain_id')}", f"{ch.get('title') or ch.get('chain_id')}: path state {state.value}",
                          st if refs else ClaimStatus.HYPOTHESIS, evidence_refs=refs, confidence=Confidence.MEDIUM,
                          source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                          limitations=["contribution of a concrete external fragment to a derived record not traced"])
            ev.claim_refs.append(c.claim_id)
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("TOOL_RESULT_REACHES_POLICY", "Tool results can influence shared memory / policy",
                              f"chain {ch.get('nodes')} is {state.value}; conditions: {ch.get('conditions') or 'none'}.",
                              status=c.claim_status, severity=Severity.HIGH, claim_refs=[c.claim_id], evidence_refs=refs,
                              scope={"chain": ch.get("chain_id")},
                              priority=RemediationPriority.P0,
                              potential_effect="content returned by a tool is transformed and published as shared rules",
                              remediation="keep tool results as data through derivation; publication of policy needs a separate authorized process",
                              closure_criterion="no derivation path from tool results to shared policy without an authorized review",
                              preconditions=list(ch.get("conditions") or []))
            ev.finding_refs.append(fnd.finding_id)
        elif state == PathState.UNKNOWN:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{ch.get('chain_id')}: {ch.get('note') or 'chain not connected in available sources'}")
        else:
            outcomes.append(ControlOutcome.PASS)
    ev.outcome = worst(outcomes)
    return ev


def _tool05(ctx: RuleContext) -> RuleEvaluation:
    signals = [f for f in ctx.doc.findings if f.plane in ("definition", "context") and f.rule_id == "TOOL-05"]
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS)
    if not signals:
        ev.interpretation = "no text signals in definitions, server instructions, resources, prompts or context files"
        return ev
    unjustified = [f for f in signals if not (f.evidence.get("matches") or f.evidence.get("chars") or f.evidence.get("words")
                                              or f.evidence.get("parameter") is not None or f.evidence.get("length"))]
    ev.finding_refs = [f.finding_id for f in signals]
    ev.outcome = ControlOutcome.INCONCLUSIVE
    ev.interpretation = (f"{len(signals)} text signal(s) recorded as hypotheses with fragment, rule and explanation; "
                         "an imperative, Unicode or a link does not prove malicious intent - review required")
    if unjustified:
        ev.limitations.append(f"{len(unjustified)} signal(s) without a stored fragment")
    return ev


def _egress01(ctx: RuleContext) -> RuleEvaluation:
    transmits = ctx.flows("transmit")
    if not transmits:
        # egress-capable tools without a declared flow: show the capability, do not guess a violation
        eg = [t.qualified_name for t in ctx.doc.all_tools() if t.egress]
        if not eg:
            return RuleEvaluation(outcome=ControlOutcome.NOT_APPLICABLE, method=Method.STATIC_ANALYSIS,
                                  interpretation="no egress-capable tool in inventory")
        return not_evaluated(f"egress-capable tools {eg} without a declared transmit flow or egress policy", ["profile.flows(transmit)", "policy.egress"])
    egress_policy = ctx.policy.get("egress") or {}
    allowed = {d.get("id"): d for d in egress_policy.get("allowed_destinations") or []}
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in transmits:
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        dest = f.get("destination")
        cats = list(f.get("data_categories_possible") or [])
        c = ctx.claim(f"CL-EGRESS-01-{f.get('id')}", f.get("statement") or f"{f.get('from')} transmits to {dest}; possible categories {cats}; filter {f.get('category_filter')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["actual transmission of client data not observed"] + list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        if not egress_policy:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{f.get('id')}: data flow shown; no egress policy to judge it against")
            continue
        pol = allowed.get(dest)
        if pol is None:
            outcomes.append(ControlOutcome.FAIL)
            reason = f"destination {dest} is not an allowed destination"
        else:
            forbidden = set(pol.get("categories_forbidden") or []) & set(cats)
            if forbidden and not f.get("category_filter"):
                outcomes.append(ControlOutcome.FAIL)
                reason = f"destination {dest} allowed, but categories {sorted(forbidden)} can be transmitted without a filter"
            else:
                outcomes.append(ControlOutcome.PASS)
                continue
        fnd = ctx.finding("EGRESS_DATA_CATEGORY_UNCONTROLLED", f"Uncontrolled transmission to {dest}", reason + ".",
                          status=st, severity=Severity.HIGH, component_refs=[f.get("from", "")], claim_refs=[c.claim_id],
                          scope={"flow": f.get("id")},
                          evidence_refs=f.get("evidence_refs") or [], priority=RemediationPriority.P1,
                          potential_effect="client identifiers or portfolio data reach an external provider inside a query",
                          remediation="control both destination and data category; filter model-composed queries before transmission",
                          closure_criterion="egress policy is enforced for destination and category; fixture observes the actual payload locally")
        ev.finding_refs.append(fnd.finding_id)
    ev.outcome = worst(outcomes)
    return ev


def _egress02(ctx: RuleContext) -> RuleEvaluation:
    cases = [t for t in ctx.doc.tests if t.rule_id == "EGRESS-02"]
    if not cases:
        return not_evaluated("no egress observation cases (local sink fixture) were run", ["control_fixtures"])
    ev = RuleEvaluation(outcome=worst(c.control_outcome for c in cases), method=Method.CONTROLLED_VALIDATION,
                        case_refs=[c.id for c in cases])
    ev.interpretation = "prepared request, gateway decision and locally received payload are recorded separately per case"
    return ev


RULES: List[Rule] = [
    Rule("TOOL-01", "2.0.0", "Контроль одобренных определений",
         "Определение связано с идентичностью сервера и согласованной версией; изменение даёт статус дрейфа.",
         "Определение связано с идентичностью сервера и согласованной версией; изменение даёт статус дрейфа",
         "tools", [["mcp_inventory", "baseline"]], [Method.PARSING],
         "every definition matches an approved baseline entry", _tool01, _tools_applicable,
         known_false_positives=["a changed hash is drift, not proof of a rug pull"],
         remediation_criterion="definitions match an approved baseline for this server identity/version"),
    Rule("TOOL-02", "2.0.0", "Корректный контракт операции",
         "Входная/выходная схемы, обработка ошибок и реально наблюдаемая версия согласованы.",
         "Входная/выходная схемы, обработка ошибок и реально наблюдаемая версия согласованы",
         "tools", [["mcp_inventory", "source_snapshot"], ["mcp_inventory"], ["source_snapshot"]], [Method.STATIC_ANALYSIS],
         "configured, source-defined and live contracts agree", _tool02, _tools_applicable,
         remediation_criterion="configured, source-defined and live schemas agree for each tool"),
    Rule("TOOL-03", "2.0.0", "Однозначное разрешение имён",
         "Namespace и выбор инструмента различают серверы; совпадение имён оценивается с учётом реального маршрутизатора.",
         "Namespace и выбор инструмента различают серверы; совпадение имён оценивается с учётом реального маршрутизатора",
         "tools", [["mcp_inventory"], ["source_snapshot"]], [Method.STATIC_ANALYSIS],
         "tool names resolve unambiguously in the real router", _tool03, _tools_applicable,
         known_false_positives=["same names under a qualified namespace"],
         remediation_criterion="the router resolves qualified names; duplicates are refused"),
    Rule("TOOL-04", "2.0.0", "Результат инструмента остаётся данными",
         "Содержимое результата не управляет политикой доступа и издателем общей памяти.",
         "Содержимое результата не управляет политикой доступа и издателем общей памяти",
         "tools", [["source_snapshot"], ["trace"]], [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "tool results never reach policy publication without an authorized process", _tool04, _tools_applicable,
         remediation_criterion="no derivation path from tool results to shared policy without authorized review",
         external_refs=[_MCP_SEC], default_priority=RemediationPriority.P0),
    Rule("TOOL-05", "2.0.0", "Обоснованность текстовых сигналов",
         "Linter сохраняет фрагмент, правило и объяснение; императив, Unicode или ссылка сами по себе не доказывают вредоносность.",
         "Linter сохраняет фрагмент, правило и объяснение; императив, Unicode или ссылка сами по себе не доказывают вредоносность",
         "tools", [["mcp_inventory"], ["source_snapshot"]], [Method.STATIC_ANALYSIS],
         "definitions and context carry no unreviewed injection signals", _tool05, _tools_applicable,
         known_false_positives=["legitimate imperatives in agent instruction files", "technical Latin tokens in Cyrillic prose"],
         limitations=["text heuristics produce hypotheses; they do not confirm compromise"],
         remediation_criterion="every signal is reviewed; confirmed ones are fixed at the definition source", external_refs=[_MCP_SEC]),
    Rule("EGRESS-01", "2.0.0", "Контроль передаваемых данных",
         "Для внешнего получателя разрешены и адресат, и категория данных; поиск учитывается как передача текста.",
         "Для внешнего получателя разрешены и адресат, и категория данных; поиск учитывается как передача текста",
         "egress", [["source_snapshot", "policy_snapshot"], ["mcp_inventory"]], [Method.STATIC_ANALYSIS, Method.POLICY_INSPECTION],
         "both destination and data category are allowed for every external transmission", _egress01, _tools_applicable,
         known_false_positives=["an allowed search provider may still receive data it must not"],
         remediation_criterion="egress policy enforced for destination and category"),
    Rule("EGRESS-02", "2.0.0", "Наблюдаемость внешних эффектов",
         "Разделяются подготовленный запрос, разрешение шлюза и фактически полученные локальной фикстурой данные.",
         "Разделяются подготовленный запрос, разрешение шлюза и фактически полученные локальной фикстурой данные",
         "egress", [["control_fixtures"]], [Method.CONTROLLED_VALIDATION],
         "external effects are observed by a local fixture, not inferred from config text", _egress02,
         lambda ctx: (Applicability.APPLICABLE, "") if ctx.doc.mode == RunMode.CONTROLLED_VALIDATION else (Applicability.NOT_APPLICABLE, "no controlled validation in this mode"),
         known_false_positives=["the text 'sinkhole' in a config does not prove traffic redirection"],
         remediation_criterion="local fixture observes the actual payload", default_priority=RemediationPriority.P1),
]
