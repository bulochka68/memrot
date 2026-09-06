"""Classifier lexicon as data (portability P1-4 / P1-5).

The verbs and signal terms the classifier reasons with are *linguistics*, not
logic: they belong to a data file, so a new stand can teach the engine its own
domain vocabulary without patching the package.

Layout of ``mcp_audit/data/lexicon.json``:

``operations``   - ``exec`` / ``delete`` / ``create`` / ``write`` / ``read`` / ``update``;
``signals``      - ``exec_description``, ``publish``, ``transmit``, ``sensitive``,
                   ``untrusted``, ``egress``, ``destructive``;
``server_kinds`` - ordered ``kind -> regex`` map used to infer a server kind;
``network_kinds``- kinds that imply network reach;
``kind_roles``   - which kinds imply exec / transmit / sensitive source / untrusted input.

Every category is ``{"words": [...], "patterns": [...]}``; ``words`` are wrapped
in one word-boundary group and ``patterns`` are appended as raw alternatives, so
the compiled expression is exactly reconstructible from the data.  A bare list is
shorthand for ``{"words": [...]}``.

A profile extends or replaces categories::

    "lexicon": {"extend":   {"operations": {"write": ["mine", "checkpoint"]}},
                "override": {"signals": {"egress": {"words": ["http", "webhook"]}}}}

``extend`` appends (keeping order, dropping duplicates), ``override`` replaces the
category as a whole.  The resulting :attr:`Lexicon.version` carries a digest of
the profile's changes, so two runs with different vocabularies are never reported
as comparable.
"""
from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "lexicon.json")

CATEGORY_GROUPS = ("operations", "signals")
LIST_GROUPS = ("network_kinds",)
MAP_GROUPS = ("server_kinds",)
ROLE_GROUP = "kind_roles"


class LexiconError(ValueError):
    """A lexicon (base file or profile section) that cannot be used as written."""


def _entry(value: Any) -> Dict[str, List[str]]:
    """Normalize a category into ``{"words": [...], "patterns": [...]}``."""
    if value is None:
        return {"words": [], "patterns": []}
    if isinstance(value, str):
        return {"words": [value], "patterns": []}
    if isinstance(value, list):
        return {"words": [str(v) for v in value], "patterns": []}
    if isinstance(value, dict):
        return {"words": [str(v) for v in (value.get("words") or [])],
                "patterns": [str(v) for v in (value.get("patterns") or [])]}
    raise LexiconError(f"category must be a list or an object with words/patterns, got {type(value).__name__}")


def build_pattern(entry: Any) -> str:
    """Compose the regular expression of one category."""
    e = _entry(entry)
    words, patterns = e["words"], e["patterns"]
    if words and patterns:
        return r"\b(" + "|".join(words) + r")\b|(" + "|".join(patterns) + ")"
    if words:
        return r"\b(" + "|".join(words) + r")\b"
    return "|".join(patterns)


def _merge(base: Any, addition: Any) -> Dict[str, List[str]]:
    b, a = _entry(base), _entry(addition)
    out = {"words": list(b["words"]), "patterns": list(b["patterns"])}
    for key in ("words", "patterns"):
        for term in a[key]:
            if term not in out[key]:
                out[key].append(term)
    return out


def _digest(obj: Any) -> str:
    import hashlib
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]


class Lexicon:
    """A compiled, immutable view of the classifier vocabulary."""

    def __init__(self, data: Dict[str, Any], *, modifications: Optional[Dict[str, Any]] = None,
                 source: str = "builtin"):
        self.data = data
        self.source = source
        self.modifications = modifications or {}
        base_version = str(data.get("lexicon_version") or "0")
        self.base_version = base_version
        self.version = base_version if not self.modifications else f"{base_version}+{source}:{_digest(self.modifications)}"
        self._rx: Dict[Tuple[str, str], Optional["re.Pattern[str]"]] = {}
        self._kinds: Optional[List[Tuple[str, "re.Pattern[str]"]]] = None

    # -- categories --------------------------------------------------------- #
    def rx(self, group: str, name: str) -> Optional["re.Pattern[str]"]:
        key = (group, name)
        if key in self._rx:
            return self._rx[key]
        raw = (self.data.get(group) or {}).get(name)
        pattern = build_pattern(raw) if raw is not None else ""
        compiled: Optional["re.Pattern[str]"] = None
        if pattern:
            try:
                compiled = re.compile(pattern, re.I)
            except re.error as exc:
                raise LexiconError(f"{group}.{name}: invalid regular expression ({exc})") from exc
        self._rx[key] = compiled
        return compiled

    def search(self, group: str, name: str, text: str) -> bool:
        """True when the category matches; an absent or empty category never matches."""
        rx = self.rx(group, name)
        return bool(rx.search(text)) if rx is not None else False

    # -- server kinds ------------------------------------------------------- #
    def server_kinds(self) -> List[Tuple[str, "re.Pattern[str]"]]:
        if self._kinds is None:
            out: List[Tuple[str, "re.Pattern[str]"]] = []
            for kind, pattern in (self.data.get("server_kinds") or {}).items():
                expr = pattern if isinstance(pattern, str) else build_pattern(pattern)
                try:
                    out.append((str(kind), re.compile(expr, re.I)))
                except re.error as exc:
                    raise LexiconError(f"server_kinds.{kind}: invalid regular expression ({exc})") from exc
            self._kinds = out
        return self._kinds

    @property
    def network_kinds(self) -> frozenset:
        return frozenset(str(k) for k in (self.data.get("network_kinds") or []))

    def kind_role(self, role: str) -> frozenset:
        return frozenset(str(k) for k in ((self.data.get(ROLE_GROUP) or {}).get(role) or []))

    # -- reporting ---------------------------------------------------------- #
    def summary(self) -> Dict[str, Any]:
        return {"lexicon_version": self.version, "base_version": self.base_version, "source": self.source,
                "modified": bool(self.modifications),
                "modifications": {mode: sorted(f"{g}.{n}" for g, names in groups.items() for n in names)
                                  for mode, groups in self.modifications.items()} if self.modifications else {}}

    def validate(self) -> List[str]:
        """Compile every category; return the problems instead of raising."""
        problems: List[str] = []
        for group in CATEGORY_GROUPS:
            for name in (self.data.get(group) or {}):
                try:
                    self.rx(group, name)
                except LexiconError as exc:
                    problems.append(str(exc))
        try:
            self.server_kinds()
        except LexiconError as exc:
            problems.append(str(exc))
        return problems


_BASE_DATA: Optional[Dict[str, Any]] = None
_BASE: Optional[Lexicon] = None


def base_lexicon() -> Lexicon:
    """The bundled lexicon (loaded once)."""
    global _BASE_DATA, _BASE
    if _BASE is None:
        with open(DATA_PATH, "r", encoding="utf-8") as fh:
            _BASE_DATA = json.load(fh)
        _BASE = Lexicon(copy.deepcopy(_BASE_DATA), source="builtin")
    return _BASE


def load_lexicon(profile: Optional[Dict[str, Any]] = None) -> Lexicon:
    """Base lexicon with the profile's ``lexicon.extend`` / ``lexicon.override`` applied."""
    spec = (profile or {}).get("lexicon") or {}
    if not spec:
        return base_lexicon()
    if not isinstance(spec, dict):
        raise LexiconError("profile.lexicon must be an object with 'extend' and/or 'override'")
    unknown = set(spec) - {"extend", "override"}
    if unknown:
        raise LexiconError(f"profile.lexicon: unknown key(s) {sorted(unknown)}; expected 'extend' / 'override'")
    data = copy.deepcopy(base_lexicon().data)
    modifications: Dict[str, Dict[str, List[str]]] = {}

    for mode in ("extend", "override"):
        block = spec.get(mode) or {}
        if not isinstance(block, dict):
            raise LexiconError(f"profile.lexicon.{mode} must be an object")
        for group, value in block.items():
            touched = modifications.setdefault(mode, {}).setdefault(group, [])
            if group in CATEGORY_GROUPS:
                if not isinstance(value, dict):
                    raise LexiconError(f"profile.lexicon.{mode}.{group} must be an object of categories")
                for name, categories in value.items():
                    data.setdefault(group, {})
                    data[group][name] = _entry(categories) if mode == "override" else _merge(data[group].get(name), categories)
                    touched.append(name)
            elif group in MAP_GROUPS:
                if not isinstance(value, dict):
                    raise LexiconError(f"profile.lexicon.{mode}.{group} must be an object of kind -> regex")
                if mode == "override":
                    data[group] = dict(value)
                else:
                    # profile kinds are tried first: a stand's own vocabulary wins over the generic one
                    data[group] = {**dict(value), **{k: v for k, v in (data.get(group) or {}).items() if k not in value}}
                touched.extend(sorted(value))
            elif group in LIST_GROUPS:
                if not isinstance(value, list):
                    raise LexiconError(f"profile.lexicon.{mode}.{group} must be a list")
                data[group] = list(value) if mode == "override" else list(dict.fromkeys(list(data.get(group) or []) + list(value)))
                touched.extend(str(v) for v in value)
            elif group == ROLE_GROUP:
                if not isinstance(value, dict):
                    raise LexiconError(f"profile.lexicon.{mode}.{ROLE_GROUP} must be an object of role -> kinds")
                for role, kinds in value.items():
                    if not isinstance(kinds, list):
                        raise LexiconError(f"profile.lexicon.{mode}.{ROLE_GROUP}.{role} must be a list of server kinds")
                    data.setdefault(ROLE_GROUP, {})
                    current = list(data[ROLE_GROUP].get(role) or [])
                    data[ROLE_GROUP][role] = list(kinds) if mode == "override" else list(dict.fromkeys(current + list(kinds)))
                    touched.append(role)
            else:
                raise LexiconError(f"profile.lexicon.{mode}: unknown group {group!r}; "
                                   f"expected one of {sorted(CATEGORY_GROUPS + MAP_GROUPS + LIST_GROUPS + (ROLE_GROUP,))}")

    source = str((profile or {}).get("profile_id") or "profile")
    lex = Lexicon(data, modifications=modifications, source=source)
    problems = lex.validate()
    if problems:
        raise LexiconError("; ".join(problems))
    return lex
