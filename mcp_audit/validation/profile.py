"""Profile linter (portability P0-3): ``python -m mcp_audit lint-profile``.

A profile is the only thing an author writes by hand, and until now nothing
checked it: a typo in ``path`` or ``symbol`` produced ``unknown``, which reads
exactly like "the code is different", and a typo in a section name was ignored
in silence.  For a mode where *only data changes*, that is the main source of
pain - so the profile is checked before the audit, and the checks are the five
things that actually go wrong:

1. structure - against ``schemas/profile.schema.json``;
2. locators  - every ``path`` exists in the source tree, every ``symbol`` resolves;
3. regexes   - every pattern (and every lexicon category) compiles;
4. rule refs - every ``rule_refs`` entry exists in the rule catalogue;
5. references - ``component`` / ``from`` / ``to`` / ``writer_principal`` /
   ``boundary`` point at declared entities.

The report also says **which rules this profile opens at all**, computed from the
rule catalogue, so the gap map is visible before the first audit rather than after
reading a wall of ``not_evaluated``.

Severity: an *error* is something the engine will misread (missing file, bad
regex, unknown rule id, dangling component reference); a *warning* is something
that is merely suspicious (an unknown section, a reference that may be a
principal declared elsewhere).  Only errors decide the exit code.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "schemas", "profile.schema.json")

FACT_GROUPS = ("flows", "auth_transitions", "background_jobs", "break_points", "token_validation")
#: sections whose entries are verified against the sources
SOURCE_GROUPS = FACT_GROUPS + ("tool_declarations",)
#: correlation markers accepted in ``chains[].rule_refs`` next to real rule ids
KNOWN_INDICATORS = ("LETHAL_TRIFECTA",)


@dataclass
class ProfileProblem:
    location: str
    message: str
    severity: str = "error"

    def __str__(self) -> str:
        return f"{self.location}  {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        return {"location": self.location, "message": self.message, "severity": self.severity}


@dataclass
class ProfileReport:
    profile_id: str
    path: Optional[str] = None
    problems: List[ProfileProblem] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    assumed_sources: List[str] = field(default_factory=list)
    plan: Dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> List[ProfileProblem]:
        return [p for p in self.problems if p.severity == "error"]

    @property
    def warnings(self) -> List[ProfileProblem]:
        return [p for p in self.problems if p.severity != "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, Any]:
        return {"profile_id": self.profile_id, "path": self.path,
                "problems": [p.to_dict() for p in self.problems], "notes": self.notes,
                "assumed_sources": self.assumed_sources, "plan": self.plan,
                "errors": len(self.errors), "warnings": len(self.warnings)}

    # -- rendering ---------------------------------------------------------- #
    def text(self, strict: bool = False) -> str:
        name = self.path or self.profile_id
        counted = self.problems if strict else self.errors
        head = f"{name}: {len(counted)} problem(s)" + (f", {len(self.warnings)} warning(s)" if not strict and self.warnings else "")
        if not self.problems:
            head = f"{name}: clean"
        lines = [head, ""]
        width = max([len(p.location) for p in self.problems] or [0])
        for p in self.errors:
            lines.append(f"  {p.location.ljust(width)}  {p.message}")
        if self.warnings:
            if self.errors:
                lines.append("")
            lines.append("warnings:")
            for p in self.warnings:
                lines.append(f"  {p.location.ljust(width)}  {p.message}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        if self.plan:
            lines += ["", self._plan_text()]
        return "\n".join(lines).rstrip() + "\n"

    def _plan_text(self) -> str:
        entries = self.plan.get("entries") or []
        planned = [e for e in entries if e.get("status") == "planned"]
        lines = [f"planned rules with this profile: {len(planned)}/{len(entries)}"
                 f"   (assumed sources: {', '.join(self.assumed_sources) or 'none'})"]
        groups: Dict[str, List[str]] = {}
        for e in entries:
            if e.get("status") == "planned":
                continue
            key = "+".join(e.get("missing_sources") or ["unknown"])
            groups.setdefault(key, []).append(e["rule_id"])
        if groups:
            parts = [f"{' '.join(sorted(rules))} ({key})" for key, rules in sorted(groups.items())]
            lines.append("  missing: " + ", ".join(parts))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #

def _known_sections() -> Set[str]:
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
            return set((json.load(fh).get("properties") or {}))
    except OSError:
        return set()


def _schema_problems(profile: Dict[str, Any]) -> List[ProfileProblem]:
    out: List[ProfileProblem] = []
    try:
        import jsonschema  # type: ignore
        with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
        validator = jsonschema.Draft202012Validator(schema)
        for e in sorted(validator.iter_errors(profile), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in e.path) or "<profile>"
            out.append(ProfileProblem(loc, e.message[:200]))
    except ImportError:
        out += _schema_fallback(profile)
    except OSError as exc:
        out.append(ProfileProblem("<schema>", f"profile schema not readable: {exc}", "warning"))
    return out


def _schema_fallback(profile: Dict[str, Any]) -> List[ProfileProblem]:
    """Structural subset check used when ``jsonschema`` is not installed."""
    out: List[ProfileProblem] = []
    if not str(profile.get("profile_id") or "").strip():
        out.append(ProfileProblem("profile_id", "missing profile_id"))
    for section, required in (("components", "id"), ("principals", "id"), ("boundaries", "id"),
                              ("memory_stores", "component_id"), ("chains", "id")):
        value = profile.get(section)
        if value is None:
            continue
        if not isinstance(value, list):
            out.append(ProfileProblem(section, f"must be a list, got {type(value).__name__}"))
            continue
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                out.append(ProfileProblem(f"{section}[{i}]", "entry must be an object"))
            elif not item.get(required):
                out.append(ProfileProblem(f"{section}[{i}]", f"missing {required!r}"))
    sf = profile.get("source_facts") or {}
    if sf and not isinstance(sf, dict):
        out.append(ProfileProblem("source_facts", "must be an object of fact groups"))
        return out
    known_groups = set(SOURCE_GROUPS) | {"components"}
    for group in sf:
        if group not in known_groups:
            out.append(ProfileProblem(f"source_facts.{group}", f"unknown fact group; known: {sorted(known_groups)}"))
    for group in SOURCE_GROUPS:
        for i, item in enumerate(sf.get(group) or []):
            if not isinstance(item, dict):
                out.append(ProfileProblem(f"source_facts.{group}[{i}]", "entry must be an object"))
            elif not item.get("path"):
                out.append(ProfileProblem(f"source_facts.{group}[{i}]", "missing 'path'"))
    return out


def _entry_label(group: str, item: Dict[str, Any], index: int) -> str:
    ident = item.get("id") or item.get("component") or item.get("symbol") or str(index)
    return f"{group}[{ident}]"


def _regex_problems(profile: Dict[str, Any]) -> List[ProfileProblem]:
    out: List[ProfileProblem] = []
    sf = profile.get("source_facts") or {}
    for group in FACT_GROUPS:
        for i, item in enumerate(sf.get(group) or []):
            if not isinstance(item, dict):
                continue
            label = _entry_label(group, item, i)
            for key in ("patterns", "negate_patterns"):
                for j, pattern in enumerate(item.get(key) or []):
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        out.append(ProfileProblem(f"{label}.{key}[{j}]", f"invalid regex: {exc}"))
            for check, cfg in (item.get("checks") or {}).items():
                pattern = (cfg or {}).get("pattern") if isinstance(cfg, dict) else None
                if pattern is None:
                    continue
                try:
                    re.compile(pattern)
                except re.error as exc:
                    out.append(ProfileProblem(f"{label}.checks.{check}", f"invalid regex: {exc}"))
    if profile.get("lexicon"):
        from ..classification.lexicon import LexiconError, load_lexicon
        try:
            load_lexicon(profile)
        except LexiconError as exc:
            out.append(ProfileProblem("lexicon", str(exc)))
    return out


def _rule_ref_problems(profile: Dict[str, Any]) -> List[ProfileProblem]:
    from ..control_rules.catalog import RULES_BY_ID
    out: List[ProfileProblem] = []
    sf = profile.get("source_facts") or {}
    containers: List[Tuple[str, Any]] = [(g, sf.get(g) or []) for g in FACT_GROUPS]
    containers.append(("chains", profile.get("chains") or []))
    for group, items in containers:
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            label = _entry_label(group, item, i)
            for ref in item.get("rule_refs") or []:
                if ref in RULES_BY_ID:
                    continue
                if group == "chains" and ref in KNOWN_INDICATORS:
                    continue           # a correlation marker, not a control
                known = ", ".join(sorted(RULES_BY_ID)[:4]) + ", …"
                out.append(ProfileProblem(f"{label}.rule_refs", f"{ref!r} is not a rule in the catalogue ({known})"))
    return out


def _declared_entities(profile: Dict[str, Any]) -> Tuple[Set[str], Set[str], Set[str]]:
    components = {str(c.get("id")) for c in (profile.get("components") or []) if isinstance(c, dict) and c.get("id")}
    components |= {str(c.get("id")) for c in ((profile.get("source_facts") or {}).get("components") or [])
                   if isinstance(c, dict) and c.get("id")}
    components |= {str(s.get("component_id")) for s in (profile.get("memory_stores") or [])
                   if isinstance(s, dict) and s.get("component_id")}
    servers = profile.get("servers") or {}
    if isinstance(servers, dict):
        components |= {str(k) for k in servers} | {str(v) for v in servers.values()}
    principals = {str(p.get("id")) for p in (profile.get("principals") or []) if isinstance(p, dict) and p.get("id")}
    boundaries = {str(b.get("id")) for b in (profile.get("boundaries") or []) if isinstance(b, dict) and b.get("id")}
    return components, principals, boundaries


def _reference_problems(profile: Dict[str, Any]) -> List[ProfileProblem]:
    components, principals, boundaries = _declared_entities(profile)
    known = components | principals
    # a profile without a principals[] section cannot have its actor names checked:
    # the actors then live in the policy, and guessing here would only produce noise
    checks_principals = bool(principals)
    out: List[ProfileProblem] = []
    sf = profile.get("source_facts") or {}

    def check(label: str, key: str, value: Any, pool: Set[str], pool_name: str, severity: str = "error",
              principal_like: bool = False) -> None:
        if not value or not isinstance(value, str):
            return
        if principal_like and not checks_principals:
            return
        if value not in pool:
            out.append(ProfileProblem(f"{label}.{key}", f"{value!r} is not declared in {pool_name}", severity))

    for group in ("tool_declarations", "token_validation", "background_jobs"):
        for i, item in enumerate(sf.get(group) or []):
            if isinstance(item, dict):
                check(_entry_label(group, item, i), "component", item.get("component"), components, "components[]")
    for i, item in enumerate(sf.get("flows") or []):
        if not isinstance(item, dict):
            continue
        label = _entry_label("flows", item, i)
        check(label, "from", item.get("from"), known, "components[] / principals[]")
        check(label, "to", item.get("to"), known, "components[] / principals[]")
        check(label, "writer_principal", item.get("writer_principal"), known, "components[] / principals[]", "warning",
              principal_like=True)
        check(label, "principal", item.get("principal"), known, "components[] / principals[]", "warning",
              principal_like=True)
        check(label, "boundary", item.get("boundary"), boundaries, "boundaries[]")
    for i, item in enumerate(sf.get("auth_transitions") or []):
        if not isinstance(item, dict):
            continue
        label = _entry_label("auth_transitions", item, i)
        check(label, "executing_component", item.get("executing_component"), components, "components[]")
        check(label, "next_component", item.get("next_component"), components, "components[]")
        check(label, "input_principal", item.get("input_principal"), known, "components[] / principals[]", "warning",
              principal_like=True)
        check(label, "boundary", item.get("boundary"), boundaries, "boundaries[]")
    for i, b in enumerate(profile.get("boundaries") or []):
        if not isinstance(b, dict):
            continue
        label = f"boundaries[{b.get('id') or i}]"
        # 'enforcement_point' is free text by design (a component, a symbol or a description) and is not checked
        check(label, "from", b.get("from"), known, "components[] / principals[]", "warning", principal_like=True)
        check(label, "to", b.get("to"), known, "components[] / principals[]", "warning", principal_like=True)
    for i, se in enumerate(profile.get("side_effects") or []):
        if isinstance(se, dict):
            check(f"side_effects[{i}]", "component", se.get("component"), components, "components[]", "warning")
    for key in (profile.get("capabilities") or {}):
        owner = str(key).split("/")[0] if "/" in str(key) else None
        if owner and owner not in ("*",) and owner not in components:
            out.append(ProfileProblem(f"capabilities[{key}]",
                                      f"{owner!r} is neither a declared component nor a server alias; "
                                      "the declaration will only apply if a server with this name exists in the inventory",
                                      "warning"))
    return out


def _locator_problems(profile: Dict[str, Any], root: str) -> List[ProfileProblem]:
    from ..adapters.source_snapshot import SourceScanner
    scanner = SourceScanner(root)
    out: List[ProfileProblem] = []
    sf = profile.get("source_facts") or {}
    for group in SOURCE_GROUPS:
        for i, item in enumerate(sf.get(group) or []):
            if not isinstance(item, dict):
                continue
            label = _entry_label(group, item, i)
            rel = item.get("path")
            if not rel:
                continue
            if not scanner.has(rel):
                out.append(ProfileProblem(f"{label}.path", f"{rel!r} does not exist under {os.path.relpath(root)}"))
                continue
            symbol = item.get("symbol")
            strategy = str(item.get("strategy") or "").lower()
            if not symbol or strategy == "regex_only":
                continue
            if not scanner.supports_symbols(rel):
                out.append(ProfileProblem(
                    f"{label}.symbol",
                    f"{rel} is .{scanner.language(rel)}: only Python has a symbol locator - "
                    "declare \"strategy\": \"regex_only\" (optionally with \"lines\") to verify this entry"))
                continue
            try:
                node = scanner.symbol_node(rel, symbol)
            except SyntaxError as exc:
                out.append(ProfileProblem(f"{label}.path", f"{rel} does not parse: {exc}"))
                continue
            if node is None:
                out.append(ProfileProblem(f"{label}.symbol", f"{symbol!r} not found in {rel}"))
    for i, comp in enumerate(profile.get("components") or []):
        if not isinstance(comp, dict):
            continue
        for path in comp.get("source_paths") or []:
            full = os.path.join(root, path)
            if not (os.path.isfile(full) or os.path.isdir(full)):
                out.append(ProfileProblem(f"components[{comp.get('id') or i}].source_paths",
                                          f"{path!r} does not exist under {os.path.relpath(root)}", "warning"))
    return out


def profile_sources(profile: Dict[str, Any], extra: Iterable[str] = ()) -> List[str]:
    """Adapter kinds this profile implies, plus the ones the caller says the manifest binds."""
    sources: Set[str] = {s.strip() for s in extra if s and s.strip()}
    sf = profile.get("source_facts") or {}
    if any(sf.get(g) for g in SOURCE_GROUPS):
        sources.add("source_snapshot")
    return sorted(sources)


def lint_profile(profile: Dict[str, Any], *, root: Optional[str] = None, path: Optional[str] = None,
                 sources: Sequence[str] = (), required_controls: Optional[Sequence[str]] = None) -> ProfileReport:
    """Check one profile and report what it opens.  Never raises on a bad profile."""
    from ..control_rules.catalog import plan as plan_rules

    report = ProfileReport(profile_id=str(profile.get("profile_id") or "<unnamed>"), path=path)
    report.problems += _schema_problems(profile)
    known = _known_sections()
    for section in profile:
        if known and section not in known and not str(section).startswith("x-"):
            report.problems.append(ProfileProblem(section, "unknown profile section: it is ignored by the engine "
                                                           "(prefix an intentional extension with 'x-')", "warning"))
    report.problems += _regex_problems(profile)
    report.problems += _rule_ref_problems(profile)
    report.problems += _reference_problems(profile)
    if root:
        if os.path.isdir(root):
            report.problems += _locator_problems(profile, root)
        else:
            report.problems.append(ProfileProblem("<root>", f"source root not found: {root}"))
    else:
        report.notes.append("no --root given: paths and symbols were not checked against a source tree")

    report.assumed_sources = profile_sources(profile, sources)
    report.plan = plan_rules(report.assumed_sources, required_controls)
    return report
