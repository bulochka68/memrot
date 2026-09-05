"""AUTH-01 … AUTH-06: identity, resource authorization and delegation (TZ §9).

Every hop is judged separately: a successful refusal at the entry API says
nothing about a backend the request never reached.  For JWT the checks of
RFC 8725 §3.8-3.9 (issuer, audience) apply; other schemes use their own
equivalent requirements (AUTH-04 is not failed by the absence of JWT).
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (Applicability, ClaimStatus, Confidence, ControlOutcome, Method, RemediationPriority,
                      Severity, SourceType)
from ..identity import token_validation_gaps, AUTH_SCHEME_REQUIREMENTS
from .base import Rule, RuleContext, RuleEvaluation, not_evaluated, status_from, worst

_RFC8725 = {"name": "RFC 8725 §3.8-3.9 (issuer / audience validation)", "url": "https://www.rfc-editor.org/rfc/rfc8725.html"}
_MCP_AUTH = {"name": "MCP Authorization Security Considerations (2026-07-28)",
             "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations",
             "note": "reference binding of requirements, not a statement about the protocol version implemented by the target"}


def _auth_applicable(ctx: RuleContext):
    if ctx.facts.get("auth_transitions") or ctx.policy.get("access_rules") or ctx.facts.get("token_validation"):
        return Applicability.APPLICABLE, ""
    if ctx.has("source_snapshot") or ctx.has("policy_snapshot"):
        return Applicability.UNKNOWN, "no transitions or access rules declared"
    return Applicability.UNKNOWN, "authorization topology unknown"


def _transitions(ctx: RuleContext) -> List[Dict[str, Any]]:
    return list(ctx.facts.get("auth_transitions") or [])


def _auth01(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("identity_binding"):
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        src = f.get("identity_source", "unknown")
        c = ctx.claim(f"CL-AUTH-01-{f.get('id')}", f.get("statement") or f"{f.get('from')}: principal established from {src}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif src == "authentication":
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("IDENTITY_FROM_UNTRUSTED_FIELD", "Input identity taken from an untrusted field",
                              f"{f.get('from')} establishes the principal from {src}.", status=st, severity=Severity.CRITICAL,
                              component_refs=[f.get("from", "")], claim_refs=[c.claim_id], evidence_refs=f.get("evidence_refs") or [],
                              priority=RemediationPriority.P0, scope={"flow": f.get("id")},
                              remediation="derive the principal from authentication only; ignore body fields and conversation text",
                              closure_criterion="request body / conversation cannot override the authenticated principal (fixture)")
            ev.finding_refs.append(fnd.finding_id)
    for p in ctx.doc.principals:
        if p.type == "end_user" and p.identity_source in ("body_field", "conversation"):
            outcomes.append(ControlOutcome.FAIL)
    if not outcomes:
        return not_evaluated("no identity-binding flows declared/verified")
    ev.outcome = worst(outcomes)
    return ev


def _auth02(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for t in _transitions(ctx):
        st = status_from([t])
        tid = t.get("id")
        decision = t.get("policy_decision", "unknown")
        if decision == "n/a":
            continue        # e.g. a delegation-only transition judged by AUTH-05
        if t.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{tid}: source not available")
            continue
        default_cond = t.get("default_condition")
        c = ctx.claim(f"CL-AUTH-02-{tid}",
                      t.get("statement") or f"{t.get('executing_component')} -> {t.get('resource')}: resource authorization {decision}"
                      + (f" (default: {default_cond})" if default_cond else ""),
                      st, evidence_refs=t.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[t.get("executing_component", "")], source_type=SourceType.SOURCE_CODE,
                      method=Method.STATIC_ANALYSIS,
                      limitations=["success of the call against the running deployment not observed"] + list(t.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        ev.boundary_refs += [t["boundary"]] if t.get("boundary") else []
        ev.component_refs.append(t.get("executing_component", ""))
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        enforced = decision == "enforced" or (decision == "conditional" and default_cond == "enforced" and not t.get("client_can_weaken"))
        if enforced:
            outcomes.append(ControlOutcome.PASS)
            continue
        outcomes.append(ControlOutcome.FAIL)
        fnd = ctx.finding("RESOURCE_AUTHORIZATION_MISSING", f"Resource authorization not enforced at {t.get('executing_component')}",
                          f"{t.get('input_principal')} -> {t.get('executing_component')} -> {t.get('operation')} {t.get('resource')}"
                          f"{' -> ' + t['next_component'] if t.get('next_component') else ''}: decision {decision}"
                          f"{', default ' + default_cond if default_cond else ''}; conditions: {t.get('conditions') or 'none'}.",
                          status=st, severity=Severity.CRITICAL, component_refs=[t.get("executing_component", "")],
                          boundary_refs=[t["boundary"]] if t.get("boundary") else [], claim_refs=[c.claim_id],
                          evidence_refs=t.get("evidence_refs") or [], preconditions=list(t.get("conditions") or []),
                          potential_effect="a valid token grants access to any object (IDOR / BAC delegated to the model)",
                          remediation="check subject -> object permission at this hop, including client -> account -> operation relations",
                          closure_criterion="each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop",
                          priority=RemediationPriority.P0, scope={"transition": tid})
        ev.finding_refs.append(fnd.finding_id)
    # controlled validation cases attached to this rule
    for case in ctx.doc.tests:
        if case.rule_id == "AUTH-02":
            outcomes.append(case.control_outcome)
            ev.case_refs.append(case.id)
            ev.method = Method.CONTROLLED_VALIDATION
    if not outcomes:
        return not_evaluated("no authorization transitions declared/verified and no control cases")
    ev.outcome = worst(outcomes)
    ev.interpretation = "each hop evaluated separately; a refusal at one hop does not cover the next"
    return ev


def _auth03(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    mandatory = set(ctx.policy.get("mandatory_server_checks") or [])
    items = [t for t in _transitions(ctx) if "client_can_weaken" in t] + ctx.flows("security_mode")
    # one root cause per component: the client-controlled mode parameter, whatever hop it weakens
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for t in items:
        groups.setdefault(t.get("executing_component") or t.get("from", ""), []).append(t)
    for comp, group in groups.items():
        known = [t for t in group if t.get("status") != "unknown"]
        if not known:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        st = status_from(known)
        weak = any(t.get("client_can_weaken") for t in known)
        params = sorted({p for t in known for p in (t.get("weakening_parameters") or [])})
        refs = [r for t in known for r in (t.get("evidence_refs") or [])]
        c = ctx.claim(f"CL-AUTH-03-{comp}", f"{comp}: client parameters can weaken mandatory checks = {weak}"
                      + (f" via {params}" if params else "") + f"; affected: {[t.get('id') for t in known]}",
                      st, evidence_refs=refs, confidence=Confidence.MEDIUM, component_refs=[comp],
                      source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["final deployment configuration not observed"])
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif weak:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("CLIENT_CAN_WEAKEN_SERVER_POLICY", f"Client parameters weaken mandatory server checks at {comp}",
                              f"{comp}: {params or 'client-controlled mode'} select(s) the security profile per request; "
                              f"affected transitions/flows: {[t.get('id') for t in known]}; mandatory checks: {sorted(mandatory) or 'undeclared'}.",
                              status=st, severity=Severity.CRITICAL, component_refs=[comp], claim_refs=[c.claim_id],
                              evidence_refs=refs, priority=RemediationPriority.P0, scope={"component": comp},
                              remediation="fix the mandatory profile server-side; ignore client mode parameters in protected deployments",
                              closure_criterion="the server defines mandatory checks; a client mode parameter cannot relax them (fixture)")
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no security-mode flows or client-weakening attributes declared")
    ev.outcome = worst(outcomes)
    return ev


def _auth04(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    expected_auth = ctx.policy.get("authentication") or {}
    for tv in ctx.facts.get("token_validation") or []:
        comp = tv.get("component", "")
        scheme = tv.get("scheme") or (expected_auth.get(comp) or {}).get("scheme") or "unknown"
        if tv.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{comp}: validation source not available")
            continue
        observed = tv.get("observed") or {}
        gaps = token_validation_gaps(observed, scheme)
        hard = [g for g in gaps if not g.endswith(":unknown")]
        unknown = [g for g in gaps if g.endswith(":unknown")]
        st = status_from([tv])
        c = ctx.claim(f"CL-AUTH-04-{comp}", f"{comp} ({scheme}): validation observed {observed}; gaps {hard or 'none'}"
                      + (f"; unknown {unknown}" if unknown else ""),
                      st, evidence_refs=tv.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[comp], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["surrounding compensating controls and the runtime result not observed"])
        ev.claim_refs.append(c.claim_id)
        ev.component_refs.append(comp)
        if scheme == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{comp}: authentication scheme unknown; equivalent requirements cannot be selected")
            continue
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif hard:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("TOKEN_VALIDATION_INCOMPLETE", f"{comp}: token validation skips {', '.join(hard)}",
                              f"scheme {scheme} requires {AUTH_SCHEME_REQUIREMENTS.get(scheme)}; observed {observed}.",
                              status=st, severity=Severity.HIGH, component_refs=[comp], claim_refs=[c.claim_id],
                              evidence_refs=tv.get("evidence_refs") or [], priority=RemediationPriority.P1,
                              potential_effect="a token issued for another audience/issuer is accepted by this service",
                              remediation="validate issuer, audience, signature, expiry and algorithm against trusted config of this service",
                              closure_criterion="each receiving service rejects tokens with a foreign issuer/audience (fixture)",
                              taxonomy=["RFC8725-3.8", "RFC8725-3.9"] if scheme == "jwt" else [])
            ev.finding_refs.append(fnd.finding_id)
        elif unknown:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        else:
            outcomes.append(ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no token-validation facts available")
    ev.outcome = worst(outcomes)
    return ev


def _auth05(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for t in _transitions(ctx):
        deleg = t.get("delegation")
        if not deleg:
            continue
        st = status_from([t])
        if t.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        bound = bool(t.get("subject_bound"))
        c = ctx.claim(f"CL-AUTH-05-{t.get('id')}", t.get("statement") or f"{t.get('executing_component')}: delegation {deleg}, subject bound {bound}",
                      st, evidence_refs=t.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[t.get("executing_component", "")], source_type=SourceType.SOURCE_CODE,
                      method=Method.STATIC_ANALYSIS, limitations=list(t.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif deleg in ("service_account_unrestricted", "passthrough_unbound") or (deleg == "service_account" and not bound):
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("UNBOUNDED_DELEGATION", f"Service credentials bypass end-user restrictions at {t.get('executing_component')}",
                              f"{t.get('executing_component')} calls {t.get('next_component') or t.get('resource')} with {deleg}; "
                              f"conditions: {t.get('conditions') or 'none'}.", status=st, severity=Severity.CRITICAL,
                              component_refs=[t.get("executing_component", "")], claim_refs=[c.claim_id],
                              evidence_refs=t.get("evidence_refs") or [], preconditions=list(t.get("conditions") or []),
                              priority=RemediationPriority.P0, scope={"transition": t.get("id")},
                              remediation="delegate with subject-bound tokens (token exchange / on-behalf-of) scoped to the task and resource",
                              closure_criterion="downstream calls carry the end-user binding; a service token alone is refused for user resources")
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no delegation attributes on transitions")
    ev.outcome = worst(outcomes)
    return ev


def _auth06(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    max_stale = float(((ctx.policy.get("authentication") or {}).get("_defaults") or {}).get("max_stale_seconds", 0) or
                      ctx.policy.get("max_stale_seconds", 0) or 0)
    for f in ctx.flows("revocation_check"):
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        c = ctx.claim(f"CL-AUTH-06-{f.get('id')}", f.get("statement") or f"{f.get('from')}: revocation checked per request = {f.get('checked_per_request')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif f.get("checked_per_request"):
            outcomes.append(ControlOutcome.PASS)
        elif max_stale and (f.get("cache_ttl_seconds") or 0) > max_stale:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("STALE_AUTHORIZATION_CACHE", f"Cached credentials outlive the policy window at {f.get('from')}",
                              f"cache ttl {f.get('cache_ttl_seconds')}s exceeds max_stale {max_stale}s.", status=st,
                              severity=Severity.MEDIUM, component_refs=[f.get("from", "")], claim_refs=[c.claim_id],
                              evidence_refs=f.get("evidence_refs") or [], priority=RemediationPriority.P2, scope={"flow": f.get("id")})
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{f.get('id')}: no policy window to compare the cache ttl against")
    if not outcomes:
        return not_evaluated("no revocation-check flows; stage D (revocation traces on the roadmap)")
    ev.outcome = worst(outcomes)
    return ev


RULES: List[Rule] = [
    Rule("AUTH-01", "2.0.0", "Доверенная входная идентичность",
         "Пользователь устанавливается аутентификацией; произвольные поля тела и содержимое диалога её не заменяют.",
         "Пользователь устанавливается аутентификацией; произвольные поля тела и содержимое диалога её не заменяют",
         "identity", [["source_snapshot"], ["policy_snapshot", "source_snapshot"]],
         [Method.STATIC_ANALYSIS, Method.CONTROLLED_VALIDATION],
         "the principal comes from authentication only", _auth01, _auth_applicable,
         remediation_criterion="body fields / conversation cannot override the authenticated principal", default_priority=RemediationPriority.P0),
    Rule("AUTH-02", "2.0.0", "Авторизация субъекта на конкретный ресурс",
         "На каждом сервисном переходе проверяется разрешение на объект, включая отношения клиент → счёт → операция.",
         "На каждом сервисном переходе проверяется разрешение на объект, включая отношения клиент → счёт → операция",
         "identity", [["source_snapshot"], ["control_fixtures"], ["trace"]],
         [Method.STATIC_ANALYSIS, Method.CONTROLLED_VALIDATION, Method.OBSERVATION],
         "each receiving service authorizes the subject for the concrete object", _auth02, _auth_applicable,
         known_false_positives=["a refusal for an invalid token is not an object-level authorization"],
         limitations=["an entry-API refusal does not cover a backend the request never reached"],
         remediation_criterion="each receiving service decides authorization for the concrete object", default_priority=RemediationPriority.P0),
    Rule("AUTH-03", "2.0.0", "Серверная политика безопасности",
         "Параметры клиента не ослабляют обязательные проверки защищённого deployment.",
         "Параметры клиента не ослабляют обязательные проверки защищённого deployment",
         "identity", [["source_snapshot"]], [Method.STATIC_ANALYSIS, Method.CONTROLLED_VALIDATION],
         "mandatory checks are fixed server-side", _auth03, _auth_applicable,
         remediation_criterion="the server defines mandatory checks; client parameters cannot relax them", default_priority=RemediationPriority.P0),
    Rule("AUTH-04", "2.0.0", "Проверка назначения и происхождения токена",
         "Каждый принимающий сервис проверяет подходящие для своей схемы issuer, audience, подпись, время и требования к алгоритму.",
         "Каждый принимающий сервис проверяет подходящие для своей схемы issuer, audience, подпись, время и требования к алгоритму",
         "identity", [["source_snapshot"], ["policy_snapshot", "source_snapshot"]],
         [Method.STATIC_ANALYSIS], "each receiving service validates the checks required by its scheme", _auth04, _auth_applicable,
         known_false_positives=["absence of JWT is not a failure; equivalent scheme requirements apply"],
         remediation_criterion="each receiving service rejects foreign issuer/audience tokens",
         external_refs=[_RFC8725, _MCP_AUTH]),
    Rule("AUTH-05", "2.0.0", "Ограниченное делегирование",
         "Передаваемые полномочия соответствуют задаче и ресурсу; сервисная учётная запись не обходит ограничения конечного пользователя.",
         "Передаваемые полномочия соответствуют задаче и ресурсу; сервисная учётная запись не обходит ограничения конечного пользователя",
         "identity", [["source_snapshot"]], [Method.STATIC_ANALYSIS, Method.CONTROLLED_VALIDATION],
         "delegated credentials are bound to the end user, task and resource", _auth05, _auth_applicable,
         remediation_criterion="downstream calls carry the end-user binding", external_refs=[_MCP_AUTH],
         default_priority=RemediationPriority.P0),
    Rule("AUTH-06", "2.0.0", "Применение изменений полномочий",
         "Смена роли, отзыв и окончание срока не оставляют действующий доступ через кэш или фоновую задачу сверх заданной политики.",
         "Смена роли, отзыв и окончание срока не оставляют действующий доступ через кэш или фоновую задачу сверх заданной политики",
         "identity", [["source_snapshot"], ["trace"]], [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "revocation and expiry take effect within the policy window", _auth06, _auth_applicable,
         limitations=["stage D: revocation traces are on the roadmap"], stage="D",
         remediation_criterion="revocation and expiry are checked within the policy window", default_priority=RemediationPriority.P2),
]
