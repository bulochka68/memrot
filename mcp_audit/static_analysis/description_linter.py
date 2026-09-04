"""Description linter.

Looks for the classic tool-poisoning signals inside free text:

  * imperatives addressed to the model ("before calling any tool, first read ...")
  * hidden / invisible Unicode (zero-width, bidi overrides, tag characters -> AML.T0068)
  * pseudo system / role markers ("<IMPORTANT>", "SYSTEM:", "ignore previous instructions")
  * secret-file references (~/.ssh, .env, id_rsa, credentials)
  * exfiltration hints (send/post/upload ... to URL, "include the contents of")
  * cross-tool steering (mentions of other tools / servers in a tool description)
  * "do not tell the user" style concealment
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Finding, Provenance, Risk, ToolRecord

# Unicode code points that are invisible or change rendering direction.
_INVISIBLE_RANGES: List[Tuple[int, int]] = [
    (0x200B, 0x200F),  # zero width space/joiner/non-joiner, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings / overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP
    (0xE0000, 0xE007F),  # Unicode TAG characters (ASCII smuggling)
    (0x00AD, 0x00AD),  # soft hyphen
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x1D173, 0x1D17A),  # musical format controls
]


def _is_invisible(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES)


_PATTERNS: List[Tuple[str, Risk, "re.Pattern[str]", str]] = [
    # (type, severity, regex, human title)
    ("HIDDEN_INSTRUCTION_MARKER", Risk.CRITICAL,
     re.compile(r"<\s*/?\s*(important|system|instructions?|hidden|secret|assistant|admin)\s*>|"
                r"\[\s*(system|hidden|internal)\s*\]|^\s*(system|assistant)\s*:", re.I | re.M),
     "Pseudo system / role marker inside a description"),
    ("INSTRUCTION_OVERRIDE", Risk.CRITICAL,
     re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)|"
                r"disregard\s+(the\s+)?(previous|prior|above|system)|"
                r"you\s+are\s+now\s+|new\s+instructions?\s*:|"
                # RU
                r"(игнорируй|забудь|не\s+обращай\s+внимани\w+\s+на)\s+(все\s+|любые\s+)?(предыдущ\w+|прошл\w+|прежн\w+|выше\w*|систем\w+)\s+(инструкц\w+|указани\w+|правил\w+|промпт\w*)|"
                r"ты\s+теперь\s+|нов\w+\s+инструкц\w+\s*:", re.I),
     "Instruction-override phrase"),
    ("CONCEALMENT", Risk.CRITICAL,
     re.compile(r"do\s*n[o']t\s+(tell|mention|inform|reveal|show|disclose|notify)\s+(this\s+to\s+)?(the\s+)?user|"
                r"without\s+(telling|informing|notifying)\s+the\s+user|"
                r"(keep|make)\s+(this|it)\s+(a\s+)?(secret|hidden|confidential)|"
                r"never\s+(mention|reveal|disclose)|"
                # RU
                r"не\s+(сообщ\w+|говор\w+|расскаж\w+|показыв\w+|раскрыв\w+|упомин\w+|уведомл\w+)\s+(это\s+)?пользовател|"
                r"(втайне|тайно|скрытно|незаметно)\s+от\s+пользовател|"
                r"никому\s+не\s+(сообщ\w+|говор\w+)", re.I),
     "Concealment directive (hide behavior from the user)"),
    ("CROSS_TOOL_STEERING", Risk.HIGH,
     re.compile(r"(before|prior\s+to|whenever|every\s+time|first)\b[^.\n]{0,60}\b(call|calling|using|use|invoke|invoking|run|running)\b[^.\n]{0,40}\b(any|other|all|this|the)\s+(other\s+)?tools?\b|"
                r"(always|must|should)\s+(first\s+)?(call|invoke|use|run)\s+(the\s+)?[`'\"]?[\w\-]+[`'\"]?\s+(tool|first)|"
                r"instead\s+of\s+(using|calling)\s+(the\s+)?[`'\"]?[\w\-]+[`'\"]?|"
                # RU: "перед вызовом любого/других тула ...", "сначала вызови ..."
                r"(перед|прежде\s+чем)\s+[^.\n]{0,40}(вызов\w+|использов\w+|обращ\w+)[^.\n]{0,40}(любо\w+|друг\w+|остальн\w+|все\w*)\s+(инструмент\w*|тул\w*)|"
                r"(сначала|всегда|обязательно)\s+(вызов\w+|используй|запуст\w+|обрат\w+)[^.\n]{0,30}(инструмент\w*|тул\w*)", re.I),
     "Steers behavior of other tool calls (shadowing / sequencing)"),
    ("AUTHORIZATION_STEERING", Risk.HIGH,
     # Description tells the model it may put an arbitrary / user-named identifier
     # into an access-scoping parameter -> IDOR / broken access control (auth to LLM).
     re.compile(r"люб\w+\s+друг\w+[^.\n]{0,50}(назов[ёе]т|укаж[ае]т|введ[ёе]т|перед[ае]ст|захочет|попрос\w+)[^.\n]{0,20}пользовател|"
                r"(значени\w+\s+из\s+пол\w+\s+user_id|user_id\s+текущ\w+\s+чат\w*)[^.\n]{0,60}люб\w+\s+друг\w+|"
                r"(любой|any)\s+(cus|client[_\s]*id|account[_\s]*id|user[_\s]*id|customer)[^.\n]{0,40}(the\s+user\s+(names|provides|specifies|wants)|назов[ёе]т|укаж[ае]т)|"
                r"identifier[^.\n]{0,30}(any\s+other[^.\n]{0,20}user)", re.I),
     "Parameter description steers the model to pass an arbitrary identifier (IDOR / broken access control)"),
    ("SECRET_FILE_REFERENCE", Risk.HIGH,
     re.compile(r"~?/?\.ssh/|id_rsa|id_ed25519|\.env\b|\.npmrc|\.pypirc|\.aws/credentials|\.netrc|"
                r"\.kube/config|\.git-credentials|/etc/(passwd|shadow)|\.bash_history|\.zsh_history|"
                r"mcp\.json|claude_desktop_config|\.cursor/mcp\.json|api[_\s-]?keys?|access[_\s-]?tokens?|"
                r"private[_\s-]?keys?|password", re.I),
     "References secret / sensitive files or credentials"),
    ("EXFIL_HINT", Risk.HIGH,
     re.compile(r"(send|post|upload|forward|transmit|email|report|submit)\b[^.\n]{0,80}\b(to\s+)?(https?://|url|endpoint|webhook|server|address)|"
                r"(include|append|attach|embed|pass)\s+(the\s+)?(contents?|value|data|output)\s+of\b|"
                r"https?://[\w.\-]+\.[a-z]{2,}(/\S*)?", re.I),
     "Data movement / external endpoint reference"),
    ("MODEL_ADDRESSED_IMPERATIVE", Risk.MEDIUM,
     re.compile(r"\b(you\s+(must|should|need\s+to|have\s+to|are\s+required\s+to)|"
                r"the\s+(assistant|model|agent|ai)\s+(must|should|will)|"
                r"it\s+is\s+(very\s+)?important\s+(that|to)|"
                r"make\s+sure\s+(to|you)|remember\s+to|always\s+(read|include|add|pass|send))\b|"
                # RU: imperatives addressed to the model ("используй этот тул первым", "ты должен", "обязательно передай")
                r"(использу\w+|вызыв\w+|запуст\w+|передав\w+|добав\w+|включ\w+)\s+(этот\s+)?(тул|инструмент)\w*\s+(первым|сначала|обязательно)|"
                r"\bты\s+(должен|обязан)\b|\b(обязательно|всегда|непременно)\s+(использу\w+|вызыв\w+|передав\w+|добав\w+)", re.I),
     "Imperative addressed to the model"),
    ("URGENCY_OR_AUTHORITY", Risk.LOW,
     re.compile(r"\b(urgent|immediately|critical\s+security|mandatory|required\s+by\s+(policy|admin|security))\b", re.I),
     "Urgency / authority pressure language"),
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
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


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
    """Return tokens that mix Latin and Cyrillic/Greek letters *within one word*.

    Legitimate multilingual text (Russian prose with Latin terms like ISIN or
    DuckDuckGo) keeps each script in separate words, so it is not flagged. A
    homoglyph attack hides a look-alike foreign letter inside one token
    (e.g. ``pаypal`` with a Cyrillic ``а``), which this catches.
    """
    hits: List[str] = []
    for word in re.findall(r"[^\W\d_]+", text, re.UNICODE):
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if "latin" in scripts and "cyrillic" in scripts:
            hits.append(word)
    return hits


def _mixed_scripts(text: str) -> bool:
    return bool(mixed_script_words(text))


def lint_text(text: str, *, where: str, server: Optional[str], tool: Optional[str],
              plane: str = "definition", id_prefix: str = "DEF") -> List[Finding]:
    """Lint a chunk of free text.  ``where`` is e.g. 'description', 'schema.path.description'."""
    findings: List[Finding] = []
    if not text:
        return findings

    invisible = find_invisible_chars(text)
    if invisible:
        smuggled = decode_tag_characters(text)
        findings.append(Finding(
            id=f"{id_prefix}-HIDDEN-UNICODE", type="HIDDEN_UNICODE", severity=Risk.CRITICAL,
            title="Hidden / invisible Unicode characters",
            description=f"{len(invisible)} invisible or bidi code point(s) found in {where}"
                        + (f"; decoded TAG payload: {smuggled!r}" if smuggled else ""),
            plane=plane, provenance=Provenance.EFFECTIVE, server=server, tool=tool,
            evidence={"where": where, "chars": invisible[:20], "decoded_tag_payload": smuggled or None},
            taxonomy=["AML.T0068"],
        ))
    mixed = mixed_script_words(text)
    if mixed:
        findings.append(Finding(
            id=f"{id_prefix}-HOMOGLYPH", type="HOMOGLYPH_MIXED_SCRIPT", severity=Risk.MEDIUM,
            title="Mixed-script (homoglyph) word",
            description=f"word(s) in {where} mix Latin and Cyrillic/Greek letters: {mixed[:5]}",
            plane=plane, provenance=Provenance.EFFECTIVE, server=server, tool=tool,
            evidence={"where": where, "words": mixed[:10]},
        ))

    # normalise before regex so invisible chars cannot split keywords
    clean = "".join(ch for ch in text if not _is_invisible(ord(ch)))
    for ftype, sev, rx, title in _PATTERNS:
        m = rx.search(clean)
        if not m:
            continue
        matches = [mm.group(0).strip() for mm in rx.finditer(clean)][:5]
        findings.append(Finding(
            id=f"{id_prefix}-{ftype}", type=ftype, severity=sev, title=title,
            description=f"{title} in {where}: {matches[0][:120]!r}",
            plane=plane, provenance=Provenance.EFFECTIVE, server=server, tool=tool,
            evidence={"where": where, "matches": matches},
        ))
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
    # Very long descriptions are a hiding place on their own.
    if len(tool.definition.description) > 2000:
        findings.append(Finding(
            id="DEF-OVERSIZED-DESCRIPTION", type="OVERSIZED_DESCRIPTION", severity=Risk.LOW,
            title="Unusually long tool description",
            description=f"description is {len(tool.definition.description)} chars",
            plane="definition", provenance=Provenance.EFFECTIVE, server=tool.server, tool=tool.name,
            evidence={"length": len(tool.definition.description)},
        ))
    # de-duplicate by (type, where)
    seen = set()
    uniq: List[Finding] = []
    for f in findings:
        key = (f.type, f.evidence.get("where"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq
