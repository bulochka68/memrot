"""MEM-01 … MEM-10: mandatory memory rules (TZ §8.2).

Inputs are generic: profile-declared flows verified by the source adapter,
the expected memory policy, memory records / events and (later) fixtures.
``scope=global`` by itself is not a violation (TZ §4): the defect is an
untrusted source deciding the audience or holding the publication right.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (Applicability, ClaimStatus, Confidence, ControlOutcome, Method, RemediationPriority,
                      Severity, SourceType, StageObservation)
from .base import Rule, RuleContext, RuleEvaluation, inconclusive, not_evaluated, refs_of, status_from, worst

_PERSONAL_AUDIENCES = ("user", "session", "tenant", "project", "group", "agent", "organization")


def _mem_applicable(ctx: RuleContext):
    if ctx.memory_types_declared() or ctx.doc.memory_stores or ctx.doc.memory_records:
        return Applicability.APPLICABLE, ""
    if ctx.has("source_snapshot") or ctx.has("policy_snapshot"):
        return Applicability.NOT_APPLICABLE, "no memory types declared by profile or policy"
    return Applicability.UNKNOWN, "memory topology unknown"


def _shared_applicable(ctx: RuleContext):
    shared = [m for m in ctx.memory_types_declared() if m.get("audience") in ("shared", "global", "all")]
    if shared:
        return Applicability.APPLICABLE, ""
    if ctx.memory_types_declared():
        return Applicability.NOT_APPLICABLE, "no shared-audience memory type is declared"
    return _mem_applicable(ctx)


def _runtime_cross_audience_reads(ctx: RuleContext) -> List[Dict[str, Any]]:
    """Retrieve events that returned another subject's personal record."""
    by_id = {r.get("memory_id"): r for r in ctx.doc.memory_records if r.get("memory_id")}
    hits = []
    for ev in ctx.doc.memory_events + ctx.doc.trace_events:
        mem = ev.get("memory") or {}
        if mem.get("operation") not in ("retrieve", "context_include"):
            continue
        rec = by_id.get(mem.get("memory_id")) or {}
        audience = rec.get("read_audience_ref") or mem.get("resolved_scope")
        owner = rec.get("subject_ref")
        if audience in _PERSONAL_AUDIENCES and owner and ev.get("principal") and owner != ev.get("principal"):
            hits.append(ev)
    return hits


# --------------------------------------------------------------------------- #
def _mem01(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    policy_types = {m.get("type"): m for m in ctx.memory_types_declared()}
    reads = ctx.flows("memory_read") + ctx.flows("context_include")
    if reads:
        for f in reads:
            mt = policy_types.get(f.get("memory_type"), {})
            audience = mt.get("audience") or f.get("audience")
            if audience not in _PERSONAL_AUDIENCES:
                continue        # shared types are judged by MEM-02/04, not by isolation
            st = status_from([f])
            if f.get("status") == "unknown":
                outcomes.append(ControlOutcome.INCONCLUSIVE)
                ev.limitations.append(f"{f.get('id')}: source not available")
                continue
            bound = bool(f.get("subject_bound", bool(f.get("filter_by"))))
            c = ctx.claim(f"CL-MEM-01-{f.get('id')}",
                          f.get("statement") or f"read path {f.get('id')} filters by {f.get('filter_by')}",
                          st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                          explanation="static reading of the retrieval filter",
                          limitations=["database ACL of the running deployment not verified; runtime reads not observed"]
                          + list(f.get("limitations") or []), component_refs=[f.get("from", "")],
                          source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
            ev.claim_refs.append(c.claim_id)
            ev.evidence_refs += f.get("evidence_refs") or []
            if st == ClaimStatus.CONTRADICTED:
                outcomes.append(ControlOutcome.INCONCLUSIVE)
                ev.limitations.append(f"{f.get('id')}: declared pattern not found; flow contradicted")
            elif bound:
                outcomes.append(ControlOutcome.PASS)
            else:
                outcomes.append(ControlOutcome.FAIL)
                fnd = ctx.finding("MEMORY_ISOLATION_MISSING", "Personal memory read without audience binding",
                                  f"{f.get('from')} reads memory type {f.get('memory_type')!r} (audience {audience}) "
                                  f"without binding the query to the requesting subject.",
                                  status=st, severity=Severity.HIGH, rationale="personal records of other subjects can enter a context",
                                  component_refs=[f.get("from", "")], claim_refs=[c.claim_id], scope={"flow": f.get("id")},
                                  evidence_refs=f.get("evidence_refs") or [], potential_effect="cross-subject memory disclosure",
                                  remediation="bind every retrieval to the authenticated subject / allowed audience",
                                  closure_criterion="retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing",
                                  priority=RemediationPriority.P0)
                ev.finding_refs.append(fnd.finding_id)
    # allowed sharing must keep working: declared sharing without a read path is a functional gap, not a violation
    sharing = (ctx.policy.get("memory_policy") or {}).get("allowed_sharing") or []
    for share in sharing:
        types = share.get("memory_types") or []
        ok = any(f.get("memory_type") in types for f in reads)
        if not ok and reads:
            ev.limitations.append(f"allowed sharing {share.get('between')} for {types}: no read path declared; sharing not shown to work")
    hits = _runtime_cross_audience_reads(ctx)
    if hits:
        refs = [h.get("_evidence_id") for h in hits if h.get("_evidence_id")]
        c = ctx.claim("CL-MEM-01-runtime-cross-read", f"{len(hits)} retrieval event(s) returned another subject's personal record",
                      ClaimStatus.RUNTIME_SUPPORTED if refs else ClaimStatus.HYPOTHESIS, evidence_refs=refs,
                      confidence=Confidence.HIGH, source_type=SourceType.RUNTIME_TRACE, method=Method.OBSERVATION)
        ev.claim_refs.append(c.claim_id)
        fnd = ctx.finding("MEMORY_ISOLATION_VIOLATED", "Cross-subject memory retrieval observed",
                          c.statement, status=c.claim_status, severity=Severity.CRITICAL,
                          observed_effect="record of another subject retrieved for a principal", claim_refs=[c.claim_id],
                          evidence_refs=refs, priority=RemediationPriority.P0,
                          memory_stages={"W": StageObservation.OBSERVED, "R": StageObservation.OBSERVED,
                                         "C": StageObservation.UNKNOWN, "B": StageObservation.NOT_EVALUATED})
        ev.finding_refs.append(fnd.finding_id)
        outcomes.append(ControlOutcome.FAIL)
        ev.method = Method.OBSERVATION
    elif ctx.doc.memory_events or ctx.doc.trace_events:
        cov = (ctx.doc.meta.get("memory_coverage") or {})
        if cov.get("retrieve"):
            outcomes.append(ControlOutcome.PASS)
            ev.interpretation = "no cross-audience retrieval in covered events"
        else:
            ev.limitations.append("retrieval events not covered by the trace; absence is not evidence")
    if not outcomes:
        return not_evaluated("no memory read paths declared/verified and no retrieval events available")
    ev.outcome = worst(outcomes)
    return ev


def _mem02(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    publishes = ctx.flows("publish")
    trusted = set()
    for mt in ctx.memory_types_declared():
        if mt.get("audience") in ("shared", "global", "all"):
            trusted |= set(mt.get("trusted_publishers") or [])
    for f in publishes:
        writer = f.get("writer_principal") or f.get("from")
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        c = ctx.claim(f"CL-MEM-02-{f.get('id')}", f.get("statement") or f"{writer} holds a publication path to {f.get('to')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      explanation="publication branch located in source", component_refs=[writer, f.get("to", "")],
                      limitations=["DB rights of the running deployment not verified",
                                   "passage of a concrete user text through the extraction step not verified"]
                      + list(f.get("limitations") or []), source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
        ev.claim_refs.append(c.claim_id)
        ev.evidence_refs += f.get("evidence_refs") or []
        role = f.get("writer_role") or (ctx.doc.component(writer).role if ctx.doc.component(writer) else "")
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.PASS)
            ev.interpretation = f"declared publication path {f.get('id')} not found in this build"
            continue
        if writer in trusted and role == "policy_publisher":
            outcomes.append(ControlOutcome.PASS)
            continue
        outcomes.append(ControlOutcome.FAIL)
        fnd = ctx.finding("USER_HANDLER_PUBLISHES_SHARED_POLICY",
                          "User-session processing is linked to shared policy publication",
                          f"{writer} (role {role or 'unknown'}) contains a branch that publishes to {f.get('to')} "
                          f"(audience {f.get('audience', 'shared')}, authority {f.get('authority', 'policy')}); "
                          f"trusted publishers: {sorted(trusted) or 'none declared'}.",
                          status=st, severity=Severity.CRITICAL, rationale="shared rules reach every subject's context",
                          root_cause="publication right is not separated from user-session processing",
                          component_refs=[writer, f.get("to", "")], boundary_refs=[f["boundary"]] if f.get("boundary") else [],
                          claim_refs=[c.claim_id], evidence_refs=f.get("evidence_refs") or [], scope={"flow": f.get("id")},
                          potential_effect="a user session can shape rules applied to all subjects",
                          limitations=["DB rights of the running deployment not verified",
                                       "passage of a concrete user text through the extraction step not verified"] + list(f.get("limitations") or []),
                          remediation="separate the shared-policy publisher; remove publication rights from the user handler at application and DB level",
                          closure_criterion="user processing holds no publication permission for shared policy; publisher has a distinct principal",
                          priority=RemediationPriority.P0,
                          memory_stages={"W": StageObservation.NOT_EVALUATED, "R": StageObservation.NOT_EVALUATED,
                                         "C": StageObservation.NOT_EVALUATED, "B": StageObservation.NOT_EVALUATED},
                          preconditions=list(f.get("conditions") or []))
        ev.finding_refs.append(fnd.finding_id)
    # service rights declared by policy vs observed store access
    for acc in ctx.flows("store_access"):
        rights = set(acc.get("rights") or [])
        if "publish" in rights or ("write" in rights and acc.get("authority") == "policy"):
            comp = ctx.doc.component(acc.get("from", ""))
            if comp and comp.role in ("user_session_handler", "background_worker") and acc.get("from") not in trusted:
                st = status_from([acc])
                c = ctx.claim(f"CL-MEM-02-rights-{acc.get('id')}", f"{acc.get('from')} has {sorted(rights)} on {acc.get('to')}",
                              st, evidence_refs=acc.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                              source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
                ev.claim_refs.append(c.claim_id)
                outcomes.append(ControlOutcome.FAIL)
    # runtime: shared-policy writes by non-publishers
    for e in ctx.doc.memory_events:
        mem = e.get("memory") or {}
        if mem.get("operation") == "write" and mem.get("resolved_scope") in ("shared", "global", "all"):
            writer = mem.get("writer") or e.get("principal")
            if writer not in trusted:
                c = ctx.claim(f"CL-MEM-02-event-{e.get('event_id')}", f"shared record {mem.get('memory_id')} written by {writer}",
                              ClaimStatus.RUNTIME_SUPPORTED if e.get("_evidence_id") else ClaimStatus.HYPOTHESIS,
                              evidence_refs=[e.get("_evidence_id")] if e.get("_evidence_id") else [],
                              confidence=Confidence.HIGH, source_type=SourceType.RUNTIME_TRACE, method=Method.OBSERVATION)
                ev.claim_refs.append(c.claim_id)
                fnd = ctx.finding("SHARED_POLICY_WRITTEN_BY_NON_PUBLISHER", "Shared policy record written by a non-publisher",
                                  c.statement, status=c.claim_status, severity=Severity.CRITICAL, claim_refs=[c.claim_id],
                                  evidence_refs=c.evidence_refs, observed_effect="shared-scope record exists with writer outside trusted publishers",
                                  priority=RemediationPriority.P0,
                                  memory_stages={"W": StageObservation.OBSERVED, "R": StageObservation.NOT_EVALUATED,
                                                 "C": StageObservation.NOT_EVALUATED, "B": StageObservation.NOT_EVALUATED})
                ev.finding_refs.append(fnd.finding_id)
                outcomes.append(ControlOutcome.FAIL)
                ev.method = Method.OBSERVATION
    if not outcomes:
        if ctx.has("source_snapshot") and not publishes:
            ev.outcome = ControlOutcome.PASS
            ev.interpretation = "no publication path from user-session processing is declared or found"
            ev.limitations.append("absence of a declared path; undeclared paths are not searched for")
            return ev
        return not_evaluated("no publication flows, store rights or memory write events available")
    ev.outcome = worst(outcomes)
    return ev


def _mem03(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("scope_decision"):
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        src = f.get("decision_source", "unknown")
        c = ctx.claim(f"CL-MEM-03-{f.get('id')}", f.get("statement") or f"owner/audience of {f.get('memory_type')} decided by {src}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif src in ("server", "policy_service"):
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("SCOPE_DECIDED_BY_UNTRUSTED_SOURCE", "Memory owner / audience decided by an untrusted source",
                              f"{f.get('from')} takes the audience of {f.get('memory_type')!r} from {src}; "
                              f"validation: {f.get('validation', 'none')}.", status=st, severity=Severity.HIGH,
                              component_refs=[f.get("from", "")], claim_refs=[c.claim_id], evidence_refs=f.get("evidence_refs") or [],
                              scope={"flow": f.get("id")}, potential_effect="metadata produced by a model or external content sets write authority",
                              remediation="resolve owner and audience server-side from the authenticated principal and policy",
                              closure_criterion="proposed scope from model/external content is advisory only; the server decides",
                              priority=RemediationPriority.P0)
            ev.finding_refs.append(fnd.finding_id)
    for e in ctx.doc.memory_events:
        mem = e.get("memory") or {}
        if mem.get("operation") == "write" and mem.get("policy_decision") in ("accepted_proposed", "none") \
                and mem.get("proposed_scope") and mem.get("proposed_by") in ("llm", "external_content", "client"):
            c = ctx.claim(f"CL-MEM-03-event-{e.get('event_id')}",
                          f"write {mem.get('memory_id')}: proposed scope {mem.get('proposed_scope')} by {mem.get('proposed_by')} accepted without a server decision",
                          ClaimStatus.RUNTIME_SUPPORTED if e.get("_evidence_id") else ClaimStatus.HYPOTHESIS,
                          evidence_refs=[e.get("_evidence_id")] if e.get("_evidence_id") else [], confidence=Confidence.HIGH,
                          source_type=SourceType.RUNTIME_TRACE, method=Method.OBSERVATION)
            ev.claim_refs.append(c.claim_id)
            outcomes.append(ControlOutcome.FAIL)
            ev.method = Method.OBSERVATION
    if not outcomes:
        return not_evaluated("no scope-decision flows or write events available")
    ev.outcome = worst(outcomes)
    return ev


def _mem04(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("context_include"):
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        mt = ctx.memory_type_policy(f.get("memory_type"))
        presented = f.get("presented_as", "data")
        authority_ok = mt.get("authority") == "policy" and set(mt.get("trusted_publishers") or []) and f.get("publisher_trusted", False)
        c = ctx.claim(f"CL-MEM-04-{f.get('id')}", f.get("statement") or f"{f.get('memory_type')} is included in context as {presented}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["actual inclusion of a record in a model request and its effect were not observed"]
                      + list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif presented == "rules" and not authority_ok:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("MEMORY_PRESENTED_AS_RULES", "Memory content presented as rules without content authority",
                              f"{f.get('from')} includes {f.get('memory_type')!r} in the {f.get('context_role', 'system')} role as rules; "
                              f"policy authority for the type: {mt.get('authority', 'undeclared')}, publisher trusted: {f.get('publisher_trusted', False)}.",
                              status=st, severity=Severity.HIGH, component_refs=[f.get("from", "")], claim_refs=[c.claim_id],
                              evidence_refs=f.get("evidence_refs") or [], scope={"flow": f.get("id")},
                              potential_effect="reference data or user-derived text gains instruction authority",
                              remediation="mark memory blocks by authority; only trusted-publisher records may be presented as rules",
                              closure_criterion="context assembly separates data blocks from instruction blocks and records the authority of each",
                              priority=RemediationPriority.P0,
                              memory_stages={"W": StageObservation.NOT_EVALUATED, "R": StageObservation.NOT_EVALUATED,
                                             "C": StageObservation.NOT_EVALUATED, "B": StageObservation.NOT_EVALUATED})
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no context-assembly flows declared/verified")
    ev.outcome = worst(outcomes)
    return ev


def _mem05(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("derivation") + ctx.flows("memory_write"):
        if "provenance_kept" not in f:
            continue
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        c = ctx.claim(f"CL-MEM-05-{f.get('id')}", f.get("statement") or f"{f.get('id')}: provenance kept = {f.get('provenance_kept')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif f.get("provenance_kept"):
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("PROVENANCE_LOST", "Derived memory loses its parents",
                              f"{f.get('from')} -> {f.get('to')}: {f.get('statement') or 'derived record is not linked to all known parents'}; "
                              f"kept fields: {f.get('provenance_fields') or 'none'}.", status=st, severity=Severity.MEDIUM,
                              component_refs=[f.get("from", "")], claim_refs=[c.claim_id], evidence_refs=f.get("evidence_refs") or [],
                              scope={"flow": f.get("id")}, potential_effect="tool results and untrusted fragments cannot be traced into derived memory; revocation cannot reach derivatives",
                              remediation="link derived records to all parent events and transformation versions; make lost lineage visible",
                              closure_criterion="every derived record carries source_event_refs / derived_from or an explicit lineage_completeness=lost",
                              priority=RemediationPriority.P1)
            ev.finding_refs.append(fnd.finding_id)
    derived = [r for r in ctx.doc.memory_records if r.get("memory_type") in
               {m.get("type") for m in ctx.memory_types_declared() if m.get("derived")}]
    if derived:
        lost = [r for r in derived if not (r.get("derived_from") or r.get("source_event_refs")) and r.get("lineage_completeness") != "lost"]
        c = ctx.claim("CL-MEM-05-records", f"{len(lost)} of {len(derived)} derived record(s) have no parent references and no explicit lost-lineage mark",
                      ClaimStatus.RUNTIME_SUPPORTED if False else ClaimStatus.STATIC_SUPPORTED,
                      evidence_refs=[r.get("_evidence_id") for r in derived if r.get("_evidence_id")][:1],
                      confidence=Confidence.MEDIUM, source_type=SourceType.MEMORY_SNAPSHOT, method=Method.POLICY_INSPECTION)
        ev.claim_refs.append(c.claim_id)
        outcomes.append(ControlOutcome.FAIL if lost else ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no derivation flows with provenance attributes and no derived records available")
    ev.outcome = worst(outcomes)
    return ev


def _mem06(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("trust_elevation") + [p for p in ctx.flows("publish") if "approval_required" in p]:
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        mt = ctx.memory_type_policy(f.get("memory_type"))
        review_required = bool(mt.get("review_required", True))
        elevates = f.get("kind") == "trust_elevation" or (review_required and not f.get("approval_required", False))
        c = ctx.claim(f"CL-MEM-06-{f.get('id')}", f.get("statement") or f"{f.get('id')}: mechanism {f.get('mechanism', 'publication without approval')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif elevates:
            outcomes.append(ControlOutcome.FAIL)
            title = ("Retelling or model confidence acts as publication permission" if f.get("kind") == "trust_elevation"
                     else "Shared publication without an approval transition")
            fnd = ctx.finding("AUTOMATIC_TRUST_ELEVATION", title,
                              f"{f.get('from')}: {f.get('statement') or 'publication proceeds without an approval step'} "
                              f"(mechanism: {f.get('mechanism', 'no approval')}; review required by policy: {review_required}).",
                              status=st, severity=Severity.HIGH, component_refs=[f.get("from", "")], claim_refs=[c.claim_id],
                              evidence_refs=f.get("evidence_refs") or [], scope={"flow": f.get("id")},
                              potential_effect="a paraphrase by the assistant or a high model confidence value becomes shared truth",
                              remediation="require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority",
                              closure_criterion="shared records carry review_state=approved with an approval_ref from a trusted publisher",
                              priority=RemediationPriority.P0)
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.PASS)
    shared_records = [r for r in ctx.doc.memory_records if (r.get("read_audience_ref") in ("shared", "global", "all"))]
    if shared_records:
        unreviewed = [r for r in shared_records if r.get("review_state") in (None, "none", "unreviewed")]
        outcomes.append(ControlOutcome.FAIL if unreviewed else ControlOutcome.PASS)
        c = ctx.claim("CL-MEM-06-records", f"{len(unreviewed)} of {len(shared_records)} shared record(s) have no review state",
                      ClaimStatus.STATIC_SUPPORTED, evidence_refs=[r.get("_evidence_id") for r in shared_records if r.get("_evidence_id")][:1],
                      confidence=Confidence.MEDIUM, source_type=SourceType.MEMORY_SNAPSHOT, method=Method.POLICY_INSPECTION)
        ev.claim_refs.append(c.claim_id)
    if not outcomes:
        return not_evaluated("no trust-elevation / approval flows and no shared records available")
    ev.outcome = worst(outcomes)
    return ev


def _mem07(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for f in ctx.flows("memory_read"):
        if "audience_filter_before_context" not in f:
            continue
        st = status_from([f])
        if f.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        c = ctx.claim(f"CL-MEM-07-{f.get('id')}", f.get("statement") or f"{f.get('id')}: audience filter before context = {f.get('audience_filter_before_context')}",
                      st, evidence_refs=f.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[f.get("from", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                      limitations=["index/cache partitioning of the running store not inspected"] + list(f.get("limitations") or []))
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
        elif f.get("audience_filter_before_context"):
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("RETRIEVAL_WITHOUT_AUDIENCE_FILTER", "Retrieval returns records before audience policy is applied",
                              f"{f.get('from')}: {f.get('statement') or 'audience policy applied after retrieval or not at all'}.",
                              status=st, severity=Severity.HIGH, component_refs=[f.get("from", "")], claim_refs=[c.claim_id],
                              evidence_refs=f.get("evidence_refs") or [], priority=RemediationPriority.P1, scope={"flow": f.get("id")},
                              remediation="apply audience filtering in the query / index partition, before ranking and context assembly",
                              closure_criterion="retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty")
            ev.finding_refs.append(fnd.finding_id)
    caches = ctx.profile.get("caches") or []
    for cache in caches:
        keyed = bool(cache.get("partition_key")) and any(k in ("audience", "subject", "tenant", "session") for k in cache["partition_key"])
        outcomes.append(ControlOutcome.PASS if keyed else ControlOutcome.INCONCLUSIVE)
        if not keyed:
            ev.limitations.append(f"cache {cache.get('id')}: partition key does not include an audience dimension or is undeclared")
    hits = _runtime_cross_audience_reads(ctx)
    if hits:
        outcomes.append(ControlOutcome.FAIL)
        ev.method = Method.OBSERVATION
    if not outcomes:
        return not_evaluated("no retrieval flows with filter attributes, no caches declared, no retrieval events")
    ev.outcome = worst(outcomes)
    return ev


def _mem08(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.OBSERVATION)
    rev_policy = (ctx.policy.get("memory_policy") or {}).get("revocation") or ctx.policy.get("revocation") or {}
    mech = (ctx.profile.get("revocation") or {}).get("mechanism")
    revokes = [e for e in ctx.doc.memory_events if (e.get("memory") or {}).get("operation") == "revoke"]
    if not revokes:
        if mech == "none" and rev_policy.get("propagate_to_derived"):
            c = ctx.claim("CL-MEM-08-no-mechanism", "the system declares no revocation mechanism while policy requires propagation to derived records",
                          ClaimStatus.HYPOTHESIS, confidence=Confidence.MEDIUM, explanation="profile declaration, not verified in source",
                          limitations=["declared by profile; not located in source"])
            fnd = ctx.finding("REVOCATION_MECHANISM_MISSING", "No revocation / derived-data withdrawal mechanism",
                              c.statement, status=ClaimStatus.HYPOTHESIS, potential_severity=Severity.MEDIUM, claim_refs=[c.claim_id],
                              priority=RemediationPriority.P2,
                              remediation="introduce revocation events with versions; re-index and drop derived records within the agreed delay",
                              closure_criterion="after revocation, source and dependent records do not return to context beyond the agreed delay (fixture)")
            ev.claim_refs.append(c.claim_id)
            ev.finding_refs.append(fnd.finding_id)
            ev.outcome = ControlOutcome.INCONCLUSIVE
            ev.interpretation = "profile declares no mechanism; source verification and fixtures pending (stage D)"
            return ev
        return not_evaluated("no revocation events; MEM-08 is a stage-D control (roadmap: revocation fixtures)")
    max_delay = float(rev_policy.get("max_delay_seconds", 0) or 0)
    outcomes: List[ControlOutcome] = []
    for r in revokes:
        mid = (r.get("memory") or {}).get("memory_id")
        ts = r.get("ts") or 0
        later = [e for e in ctx.doc.memory_events if (e.get("memory") or {}).get("memory_id") == mid and
                 (e.get("memory") or {}).get("operation") in ("retrieve", "context_include") and (e.get("ts") or 0) > ts + max_delay]
        jobs = [e for e in ctx.doc.memory_events if (e.get("job") or {}).get("status") in ("pending", "running") and
                mid in ((e.get("job") or {}).get("memory_ids") or [])]
        if jobs:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"revocation of {mid}: background job still {jobs[0]['job']['status']}; consistency window not closed, clean result not concluded")
            continue
        if later:
            outcomes.append(ControlOutcome.FAIL)
            c = ctx.claim(f"CL-MEM-08-{mid}", f"record {mid} returned to context {len(later)} time(s) after revocation beyond {max_delay}s",
                          ClaimStatus.RUNTIME_SUPPORTED if later[0].get("_evidence_id") else ClaimStatus.HYPOTHESIS,
                          evidence_refs=[e.get("_evidence_id") for e in later if e.get("_evidence_id")], confidence=Confidence.HIGH,
                          source_type=SourceType.RUNTIME_TRACE, method=Method.OBSERVATION)
            ev.claim_refs.append(c.claim_id)
            fnd = ctx.finding("REVOKED_RECORD_STILL_SERVED", "Revoked record still returned to context", c.statement,
                              status=c.claim_status, severity=Severity.HIGH, claim_refs=[c.claim_id], evidence_refs=c.evidence_refs,
                              priority=RemediationPriority.P1, scope={"memory_id": mid})
            ev.finding_refs.append(fnd.finding_id)
        else:
            cov = ctx.doc.meta.get("memory_coverage") or {}
            outcomes.append(ControlOutcome.PASS if cov.get("retrieve") else ControlOutcome.INCONCLUSIVE)
    ev.outcome = worst(outcomes)
    return ev


def _mem09(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.STATIC_ANALYSIS)
    outcomes: List[ControlOutcome] = []
    for job in ctx.facts.get("background_jobs") or []:
        if job.get("status") == "unknown":
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        st = status_from([job])
        c = ctx.claim(f"CL-MEM-09-{job.get('id')}", job.get("statement") or f"background job {job.get('id')} located",
                      st, evidence_refs=job.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      component_refs=[job.get("component", "")], source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
        ev.claim_refs.append(c.claim_id)
        problems = []
        if job.get("carries_identity") is False:
            problems.append("does not carry the originating identity")
        if job.get("idempotent") is False:
            problems.append("not idempotent (retries can duplicate publications)")
        if job.get("checks_policy_revision") is False:
            problems.append("does not check the policy revision (can publish cancelled data)")
        if problems:
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("BACKGROUND_JOB_CONSISTENCY", f"Background job {job.get('id')} lacks consistency guarantees",
                              f"{job.get('component')}: " + "; ".join(problems) + ".", status=st, severity=Severity.MEDIUM,
                              component_refs=[job.get("component", "")], claim_refs=[c.claim_id], evidence_refs=job.get("evidence_refs") or [],
                              priority=RemediationPriority.P2, scope={"job": job.get("id")},
                              remediation="carry job/parent ids, idempotency keys and the policy revision through background processing",
                              closure_criterion="retries, concurrent sessions and delayed jobs keep the original identity and skip cancelled data (fixture)")
            ev.finding_refs.append(fnd.finding_id)
        elif any(k in job for k in ("carries_identity", "idempotent", "checks_policy_revision")):
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"job {job.get('id')}: consistency attributes not declared")
    if not outcomes:
        return not_evaluated("no background jobs declared; runtime job events are a stage-D source")
    ev.outcome = worst(outcomes)
    return ev


def _mem10(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, method=Method.POLICY_INSPECTION)
    outcomes: List[ControlOutcome] = []
    observed = {f.get("memory_type"): f for f in ctx.flows("retention")}
    for mt in ctx.memory_types_declared():
        t = mt.get("type")
        expected = (ctx.memory_type_policy(t).get("retention") or mt.get("retention") or {})
        obs = observed.get(t)
        if not expected:
            ev.limitations.append(f"{t}: no retention expectation in policy")
            continue
        if obs is None:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            ev.limitations.append(f"{t}: retention behaviour not located in source")
            continue
        st = status_from([obs])
        c = ctx.claim(f"CL-MEM-10-{t}", obs.get("statement") or f"{t}: ttl={obs.get('ttl_seconds')} via {obs.get('mechanism')}",
                      st, evidence_refs=obs.get("evidence_refs") or [], confidence=Confidence.MEDIUM,
                      source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS)
        ev.claim_refs.append(c.claim_id)
        if st == ClaimStatus.CONTRADICTED:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            continue
        ttl = obs.get("ttl_seconds")
        exp_ttl = expected.get("ttl_seconds") or (expected.get("ttl_days", 0) * 86400 if expected.get("ttl_days") else None)
        if exp_ttl and (ttl is None or ttl > exp_ttl):
            outcomes.append(ControlOutcome.FAIL)
            fnd = ctx.finding("RETENTION_UNDEFINED_OR_EXCEEDED", f"Retention for memory type {t} is undefined or exceeds policy",
                              f"policy expects ttl<={exp_ttl}s; observed ttl={ttl} (mechanism {obs.get('mechanism', 'none')}).",
                              status=st, severity=Severity.MEDIUM, claim_refs=[c.claim_id], evidence_refs=obs.get("evidence_refs") or [],
                              priority=RemediationPriority.P2, scope={"memory_type": t},
                              remediation="define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration",
                              closure_criterion="each memory type has a retention policy in config and a cleanup mechanism with maintenance events")
            ev.finding_refs.append(fnd.finding_id)
        else:
            outcomes.append(ControlOutcome.PASS)
    if not outcomes:
        return not_evaluated("no retention expectations or observations available")
    ev.outcome = worst(outcomes)
    return ev


RULES: List[Rule] = [
    Rule("MEM-01", "2.0.0", "Изоляция памяти согласно бизнес-политике",
         "Личные записи доступны только разрешённой аудитории; разрешённое совместное использование продолжает работать.",
         "Личные записи доступны только разрешённой аудитории; разрешённое совместное использование продолжает работать",
         "memory", [["source_snapshot"], ["policy_snapshot", "memory_event_snapshot"], ["trace"], ["control_fixtures"]],
         [Method.STATIC_ANALYSIS, Method.POLICY_INSPECTION, Method.OBSERVATION, Method.CONTROLLED_VALIDATION],
         "retrieval of personal memory is bound to the requesting subject / allowed audience", _mem01, _mem_applicable,
         known_false_positives=["shared reference data explicitly allowed by policy", "agents sharing memory by design"],
         limitations=["scope/tenant fields in a document do not prove access control enforcement"],
         remediation_criterion="personal retrieval paths carry an audience filter; fixture read for a foreign subject is empty",
         external_refs=[{"name": "OWASP ASI06 Memory & Context Poisoning", "url": "https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/"}],
         default_priority=RemediationPriority.P0),
    Rule("MEM-02", "2.0.0", "Разделение записи пользовательских данных и публикации общей политики",
         "Сервис обработки пользовательской сессии не может публиковать общие правила; издатель имеет отдельное полномочие.",
         "Сервис обработки пользовательской сессии не может публиковать общие правила; издатель имеет отдельное полномочие",
         "memory", [["source_snapshot"], ["policy_snapshot", "source_snapshot"], ["memory_event_snapshot"]],
         [Method.STATIC_ANALYSIS, Method.POLICY_INSPECTION, Method.OBSERVATION],
         "no code path or service right lets user-session processing publish shared policy", _mem02, _shared_applicable,
         known_false_positives=["shared reference data published by a trusted process"],
         remediation_criterion="user processing holds no publication permission for shared policy; the publisher is a distinct principal",
         default_priority=RemediationPriority.P0),
    Rule("MEM-03", "2.0.0", "Сервер определяет владельца и разрешённую область",
         "Метаданные от LLM или внешнего содержимого не устанавливают полномочия записи.",
         "Метаданные от LLM или внешнего содержимого не устанавливают полномочия записи",
         "memory", [["source_snapshot"], ["memory_event_snapshot"]],
         [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "owner and audience are resolved server-side from the authenticated principal and policy", _mem03, _mem_applicable,
         remediation_criterion="proposed scope from a model or external content is advisory; the server decides", default_priority=RemediationPriority.P0),
    Rule("MEM-04", "2.0.0", "Разделение данных и инструкций",
         "Справочные записи не получают права менять общие правила из-за роли сообщения или пересказа.",
         "Справочные записи не получают права менять общие правила из-за роли сообщения или пересказа",
         "memory", [["source_snapshot"], ["trace"]],
         [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "context blocks carry an authority marking; data blocks are not presented as rules", _mem04, _mem_applicable,
         remediation_criterion="context assembly separates data from instructions and records each block's authority",
         default_priority=RemediationPriority.P0),
    Rule("MEM-05", "2.0.0", "Сохранение происхождения при преобразовании",
         "Производная запись связана со всеми известными родителями; потеря связи видима.",
         "Производная запись связана со всеми известными родителями; потеря связи видима",
         "memory", [["source_snapshot"], ["memory_event_snapshot"]],
         [Method.STATIC_ANALYSIS, Method.POLICY_INSPECTION],
         "derived records reference their parents or are explicitly marked as lineage-lost", _mem05, _mem_applicable,
         remediation_criterion="every derived record carries parent references or an explicit lost-lineage mark"),
    Rule("MEM-06", "2.0.0", "Отсутствие автоматического повышения доверия",
         "Пересказ ассистентом и высокая LLM-confidence не являются разрешением публикации.",
         "Пересказ ассистентом и высокая LLM-confidence не являются разрешением публикации",
         "memory", [["source_snapshot"], ["memory_event_snapshot"]],
         [Method.STATIC_ANALYSIS, Method.POLICY_INSPECTION],
         "publication to a shared audience requires an authorized review/approval transition", _mem06, _shared_applicable,
         remediation_criterion="shared records carry an approved review state from a trusted publisher", default_priority=RemediationPriority.P0),
    Rule("MEM-07", "2.0.0", "Изоляция retrieval, кэша и индекса",
         "Политика аудитории применяется до выдачи контекста; кэш не смешивает неразрешённые области.",
         "Политика аудитории применяется до выдачи контекста; кэш не смешивает неразрешённые области",
         "memory", [["source_snapshot"], ["memory_event_snapshot"], ["trace"]],
         [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "audience policy is applied before context delivery; caches and indexes are partitioned by audience", _mem07, _mem_applicable,
         known_false_positives=["similarity / top_k alone says nothing about rights"],
         remediation_criterion="retrieval, cache keys and index partitions include the audience"),
    Rule("MEM-08", "2.0.0", "Отзыв производных данных",
         "После отзыва источник и зависящие от него неприемлемые записи не возвращаются в контекст за пределами заданного срока.",
         "После отзыва источник и зависящие от него неприемлемые записи не возвращаются в контекст за пределами заданного срока",
         "memory", [["memory_event_snapshot"], ["control_fixtures"], ["policy_snapshot"]],
         [Method.OBSERVATION, Method.CONTROLLED_VALIDATION],
         "revoked sources and their derivatives leave retrieval within the agreed delay", _mem08, _mem_applicable,
         limitations=["stage D: revocation fixtures and index-version tracking are on the roadmap"],
         remediation_criterion="after revocation, source and dependents do not return to context beyond the agreed delay", stage="D",
         default_priority=RemediationPriority.P2),
    Rule("MEM-09", "2.0.0", "Корректность фоновых операций",
         "Повторы, конкурирующие сессии и отложенные задачи сохраняют исходную идентичность и не публикуют отменённые данные.",
         "Повторы, конкурирующие сессии и отложенные задачи сохраняют исходную идентичность и не публикуют отменённые данные",
         "memory", [["source_snapshot"], ["trace"]],
         [Method.STATIC_ANALYSIS, Method.OBSERVATION],
         "background processing keeps identity, idempotency and policy revision", _mem09, _mem_applicable,
         limitations=["stage D: runtime job events (job ids, parent ids) are on the roadmap"],
         remediation_criterion="background jobs carry job/parent ids, idempotency keys and the policy revision", stage="D",
         default_priority=RemediationPriority.P2),
    Rule("MEM-10", "2.0.0", "Управляемое хранение",
         "TTL, ограничение объёма, обновление и очистка определены по типам памяти; старые записи не восстанавливаются неуправляемо.",
         "TTL, ограничение объёма, обновление и очистка определены по типам памяти; старые записи не восстанавливаются неуправляемо",
         "memory", [["policy_snapshot", "source_snapshot"]],
         [Method.POLICY_INSPECTION, Method.STATIC_ANALYSIS],
         "each memory type has a defined retention and a cleanup mechanism", _mem10, _mem_applicable,
         limitations=["stage D: maintenance events are on the roadmap"],
         remediation_criterion="each memory type has retention in config and a cleanup mechanism", stage="D",
         default_priority=RemediationPriority.P2),
]
