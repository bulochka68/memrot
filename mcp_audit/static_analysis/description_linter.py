"""Description linter: text *signals* inside definitions, instructions and context files.

Every signal keeps the matched fragment, the rule that fired and an
explanation, and is filed as a **hypothesis** under TOOL-05: an imperative,
an invisible code point or a link does not prove malicious intent by itself
(TZ §10.2).  The original text is never modified; the normalized copy used
for matching is separate from the evidence (TZ §6.6).

Signals (bilingual EN/RU):
  * imperatives addressed to the model, instruction overrides, concealment
  * hidden / invisible Unicode (zero-width, bidi, TAG smuggling -> AML.T0068), homoglyph words
  * pseudo system / role markers
  * secret-file references, exfiltration hints, cross-tool steering
  * authorization steering (arbitrary identifiers into access-scoping parameters)
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import ClaimStatus, Finding, Severity, ToolRecord

RULE_ID = "TOOL-05"
SIGNAL_LIMITATION = "text heuristic: the signal is a hypothesis, not proof of compromise or of a right to change the server"

_INVISIBLE_RANGES: List[Tuple[int, int]] = [
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF),
    (0xE0000, 0xE007F), (0x00AD, 0x00AD), (0x180E, 0x180E), (0x034F, 0x034F), (0x1D173, 0x1D17A),
]


def _is_invisible(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES)


# (type, potential severity, regex, title, explanation)
_PATTERNS: List[Tuple[str, Severity, "re.Pattern[str]", str, str]] = [
    ("HIDDEN_INSTRUCTION_MARKER", Severity.CRITICAL,
     re.compile(r"<\s*/?\s*(important|system|instructions?|hidden|secret|assistant|admin)\s*>|"
                r"\[\s*(system|hidden|internal)\s*\]|^\s*(system|assistant)\s*:", re.I | re.M),
     "Pseudo system / role marker inside a description",
     "markup that imitates a system or role message is a classic tool-poisoning carrier"),
    ("INSTRUCTION_OVERRIDE", Severity.CRITICAL,
     re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)|"
                r"disregard\s+(the\s+)?(previous|prior|above|system)|"
                r"you\s+are\s+now\s+|new\s+instructions?\s*:|"
                r"(игнорируй|забудь|не\s+обращай\s+внимани\w+\s+на)\s+(все\s+|любые\s+)?(предыдущ\w+|прошл\w+|прежн\w+|выше\w*|систем\w+)\s+(инструкц\w+|указани\w+|правил\w+|промпт\w*)|"
                r"ты\s+теперь\s+|нов\w+\s+инструкц\w+\s*:", re.I),
     "Instruction-override phrase", "phrase that tries to cancel prior instructions"),
    ("CONCEALMENT", Severity.CRITICAL,
     re.compile(r"do\s*n[o']t\s+(tell|mention|inform|reveal|show|disclose|notify)\s+(this\s+to\s+)?(the\s+)?user|"
                r"without\s+(telling|informing|notifying)\s+the\s+user|"
                r"(keep|make)\s+(this|it)\s+(a\s+)?(secret|hidden|confidential)|"
                r"never\s+(mention|reveal|disclose)|"
                r"не\s+(сообщ\w+|говор\w+|расскаж\w+|показыв\w+|раскрыв\w+|упомин\w+|уведомл\w+)\s+(это\s+)?пользовател|"
                r"(втайне|тайно|скрытно|незаметно)\s+от\s+пользовател|"
                r"никому\s+не\s+(сообщ\w+|говор\w+)", re.I),
     "Concealment directive (hide behaviour from the user)", "asks the model to hide an action from the user"),
    ("CROSS_TOOL_STEERING", Severity.HIGH,
     re.compile(r"(before|prior\s+to|whenever|every\s+time|first)\b[^.\n]{0,60}\b(call|calling|using|use|invoke|invoking|run|running)\b[^.\n]{0,40}\b(any|other|all|this|the)\s+(other\s+)?tools?\b|"
                r"(always|must|should)\s+(first\s+)?(call|invoke|use|run)\s+(the\s+)?[`'\"]?[\w\-]+[`'\"]?\s+(tool|first)|"
                r"instead\s+of\s+(using|calling)\s+(the\s+)?[`'\"]?[\w\-]+[`'\"]?|"
                r"(перед|прежде\s+чем)\s+[^.\n]{0,40}(вызов\w+|использов\w+|обращ\w+)[^.\n]{0,40}(любо\w+|друг\w+|остальн\w+|все\w*)\s+(инструмент\w*|тул\w*)|"
                r"(сначала|всегда|обязательно)\s+(вызов\w+|используй|запуст\w+|обрат\w+)[^.\n]{0,30}(инструмент\w*|тул\w*)", re.I),
     "Steers behaviour of other tool calls (shadowing / sequencing)", "a definition that sequences or replaces other tools"),
    ("AUTHORIZATION_STEERING", Severity.HIGH,
     re.compile(r"люб\w+\s+друг\w+[^.\n]{0,50}(назов[ёе]т|укаж[ае]т|введ[ёе]т|перед[ае]ст|захочет|попрос\w+)[^.\n]{0,20}пользовател|"
                r"(значени\w+\s+из\s+пол\w+\s+user_id|user_id\s+текущ\w+\s+чат\w*)[^.\n]{0,60}люб\w+\s+друг\w+|"
                r"(любой|any)\s+(cus|client[_\s]*id|account[_\s]*id|user[_\s]*id|customer)[^.\n]{0,40}(the\s+user\s+(names|provides|specifies|wants)|назов[ёе]т|укаж[ае]т)|"
                r"identifier[^.\n]{0,30}(any\s+other[^.\n]{0,20}user)", re.I),
     "Parameter description steers the model to pass an arbitrary identifier (IDOR / broken access control)",
     "access scoping delegated to the model's choice of identifier; enforcement must be checked at the server (AUTH-02)"),
    ("SECRET_FILE_REFERENCE", Severity.HIGH,
     re.compile(r"~?/?\.ssh/|id_rsa|id_ed25519|\.env\b|\.npmrc|\.pypirc|\.aws/credentials|\.netrc|"
                r"\.kube/config|\.git-credentials|/etc/(passwd|shadow)|\.bash_history|\.zsh_history|"
                r"mcp\.json|claude_desktop_config|\.cursor/mcp\.json|api[_\s-]?keys?|access[_\s-]?tokens?|"
                r"private[_\s-]?keys?|password", re.I),
     "References secret / sensitive files or credentials", "mentions of secret material inside a definition"),
    ("EXFIL_HINT", Severity.HIGH,
     re.compile(r"(send|post|upload|forward|transmit|email|report|submit)\b[^.\n]{0,80}\b(to\s+)?(https?://|url|endpoint|webhook|server|address)|"
                r"(include|append|attach|embed|pass)\s+(the\s+)?(contents?|value|data|output)\s+of\b|"
                r"https?://[\w.\-]+\.[a-z]{2,}(/\S*)?", re.I),
     "Data movement / external endpoint reference", "a link or a data-movement phrase; legitimate in many descriptions"),
    ("MODEL_ADDRESSED_IMPERATIVE", Severity.MEDIUM,
     re.compile(r"\b(you\s+(must|should|need\s+to|have\s+to|are\s+required\s+to)|"
                r"the\s+(assistant|model|agent|ai)\s+(must|should|will)|"
                r"it\s+is\s+(very\s+)?important\s+(that|to)|"
                r"make\s+sure\s+(to|you)|remember\s+to|always\s+(read|include|add|pass|send))\b|"
                r"(использу\w+|вызыв\w+|запуст\w+|передав\w+|добав\w+|включ\w+)\s+(этот\s+)?(тул|инструмент)\w*\s+(первым|сначала|обязательно)|"
                r"\bты\s+(должен|обязан)\b|\b(обязательно|всегда|непременно)\s+(использу\w+|вызыв\w+|передав\w+|добав\w+)", re.I),
     "Imperative addressed to the model", "imperatives are normal in instructions; suspicious only with other signals"),
    ("URGENCY_OR_AUTHORITY", Severity.LOW,
     re.compile(r"\b(urgent|immediately|critical\s+security|mandatory|required\s+by\s+(policy|admin|security))\b", re.I),
     "Urgency / authority pressure language", "pressure language; weak signal"),
]


def find_invisible_chars(text: str) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []
    for idx, ch in enumerate(text):
        cp = ord(ch)
        if _is_invisible(cp) or unicodedata.category(ch) in ("Cf",) and cp not in (0x200D,) or unicodedata.category(ch) == "Co":
            hits.append({"index": idx, "codepoint": f"U+{cp:04X}", "name": unicodedata.name(ch, "UNKNOWN")})
    return hits


def decode_tag_characters(text: str) -> str:
    """Decode ASCII smuggled via Unicode TAG block (U+E0000..U+E007F)."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


def _script_of(ch: str) -> Optional[str]:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith(("CYRILLIC", "GREEK")):
        return "cyrillic"
    return None


def mixed_script_words(text: str) -> List[str]:
    """Tokens mixing Latin and Cyrillic/Greek letters *within one word* (homoglyph attack);
    Cyrillic prose with Latin technical tokens is not flagged."""
    hits: List[str] = []
    for word in re.findall(r"[^\W\d_]+", text, re.UNICODE):
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if "latin" in scripts and "cyrillic" in scripts:
            hits.append(word)
    return hits


def normalize_for_matching(text: str) -> str:
    """Strip invisible code points so they cannot split keywords.  The original is kept as evidence."""
    return "".join(ch for ch in text if not _is_invisible(ord(ch)))


def _signal(code: str, title: str, description: str, potential: Severity, *, where: str, server: Optional[str],
            tool: Optional[str], plane: str, evidence: Dict[str, object], taxonomy: Iterable[str] = (),
            explanation: str = "") -> Finding:
    return Finding(
        code=code, title=title, description=description, rule_id=RULE_ID, plane=plane,
        verification_status=ClaimStatus.HYPOTHESIS, potential_severity=potential,
        severity_rationale="potential severity if the signal is confirmed as poisoning",
        requirement="TOOL-05: text signals are recorded with fragment, rule and explanation and remain hypotheses",
        expected_invariant="definitions and context carry no unreviewed injection signals",
        server=server, tool=tool, evidence={**evidence, "where": where, "rule": code, "explanation": explanation},
        taxonomy=list(taxonomy), limitations=[SIGNAL_LIMITATION],
        remediation="review the fragment at its source; if confirmed, fix the definition and re-baseline",
        closure_criterion="the fragment is removed or justified by the definition owner",
        potential_effect="model steering through definition text (tool poisoning) if the signal is real",
    )


def lint_text(text: str, *, where: str, server: Optional[str], tool: Optional[str],
              plane: str = "definition") -> List[Finding]:
    """Lint a chunk of free text.  ``where`` is e.g. 'description', 'inputSchema.path.description'."""
    findings: List[Finding] = []
    if not text:
        return findings
    invisible = find_invisible_chars(text)
    if invisible:
        smuggled = decode_tag_characters(text)
        findings.append(_signal(
            "HIDDEN_UNICODE", "Hidden / invisible Unicode characters",
            f"{len(invisible)} invisible or bidi code point(s) found in {where}"
            + (f"; decoded TAG payload: {smuggled!r}" if smuggled else ""), Severity.CRITICAL,
            where=where, server=server, tool=tool, plane=plane,
            evidence={"chars": invisible[:20], "decoded_tag_payload": smuggled or None, "original_length": len(text)},
            taxonomy=["AML.T0068"], explanation="invisible code points can hide instructions from a human reviewer"))
    mixed = mixed_script_words(text)
    if mixed:
        findings.append(_signal(
            "HOMOGLYPH_MIXED_SCRIPT", "Mixed-script (homoglyph) word",
            f"word(s) in {where} mix Latin and Cyrillic/Greek letters: {mixed[:5]}", Severity.MEDIUM,
            where=where, server=server, tool=tool, plane=plane, evidence={"words": mixed[:10]},
            explanation="look-alike letters can disguise a name or a link"))
    clean = normalize_for_matching(text)
    for code, sev, rx, title, explanation in _PATTERNS:
        m = rx.search(clean)
        if not m:
            continue
        matches = [mm.group(0).strip() for mm in rx.finditer(clean)][:5]
        findings.append(_signal(
            code, title, f"{title} in {where}: {matches[0][:120]!r}", sev, where=where, server=server, tool=tool,
            plane=plane, evidence={"matches": matches, "fragment": matches[0][:200]}, explanation=explanation))
    return findings


def _walk_schema_text(schema: object, path: str = "schema") -> Iterable[Tuple[str, str]]:
    if isinstance(schema, dict):
        for key in ("description", "title", "default", "examples", "const", "pattern"):
            val = schema.get(key)
            if isinstance(val, str):
                yield f"{path}.{key}", val
            elif isinstance(val, list):
                for i, v in enumerate(val):
                    if isinstance(v, str):
                        yield f"{path}.{key}[{i}]", v
        for k, v in schema.items():
            if isinstance(v, (dict, list)) and k not in ("examples",):
                yield from _walk_schema_text(v, f"{path}.{k}")
    elif isinstance(schema, list):
        for i, v in enumerate(schema):
            yield from _walk_schema_text(v, f"{path}[{i}]")


def lint_tool(tool: ToolRecord) -> List[Finding]:
    """Lint a tool's description and every text field inside its schema."""
    findings = lint_text(tool.definition.description, where="description", server=tool.server, tool=tool.name)
    if tool.definition.title:
        findings += lint_text(tool.definition.title, where="title", server=tool.server, tool=tool.name)
    for where, text in _walk_schema_text(tool.definition.input_schema, "inputSchema"):
        findings += lint_text(text, where=where, server=tool.server, tool=tool.name)
    if len(tool.definition.description) > 2000:
        findings.append(_signal(
            "OVERSIZED_DESCRIPTION", "Unusually long tool description",
            f"description is {len(tool.definition.description)} chars", Severity.LOW, where="description",
            server=tool.server, tool=tool.name, plane="definition",
            evidence={"length": len(tool.definition.description)}, explanation="long descriptions are a hiding place"))
    seen = set()
    uniq: List[Finding] = []
    for f in findings:
        key = (f.code, f.evidence.get("where"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq
