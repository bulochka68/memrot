"""CLI presentation layer: banner, panels, tables, progress.

Pure stdlib (box-drawing via plain string formatting) except for ``tqdm``,
which is soft-imported and gracefully degrades to a plain print-based
progress indicator when unavailable -- the attack engine itself (``runner/``,
``adapters/``, ``detectors/``) stays free of any hard third-party dependency;
this module is the one opt-in exception, and only for cosmetics, matching the
same "graceful degrade, never a hard requirement" pattern already used for
``LLMJudgeDetector``'s fallback-to-literal.

Visual reference: LLAMATOR's CLI output (boxed banner/config/legend, a
results table with a Confirmed/Clean/Errors/Strength-bar breakdown, a
plain-language summary). Adapted for this project's own verdict vocabulary
(``CONFIRMED``/``CLEAN``/``ERROR``/``INVALID``/``NOT_EVALUATED`` -- never
collapsed into just "broken/resilient", see ``models.py``'s own "never
fabricate a percentage" rule) and its own two-phase flow: an audit summary
is shown *before* the attack table when ``--audit`` is used, because this
project's whole premise is that audit findings drive attack selection, not
the other way around.
"""
from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:
    from tqdm import tqdm as _tqdm
except ImportError:  # pragma: no cover -- exercised by the "tqdm missing" fallback path
    _tqdm = None

WIDTH = 80
_INNER = WIDTH - 2


def fancy_enabled(no_fancy: bool, force_fancy: bool) -> bool:
    """Fancy output is opt-out, not opt-in: default to on for an interactive
    terminal, off when stdout is piped/captured (a pytest run, a script, CI)
    so the machine-readable status line on stderr stays the only output a
    non-interactive caller has to parse. ``--fancy``/``--no-fancy`` override
    the auto-detection either way."""
    if no_fancy:
        return False
    if force_fancy:
        return True
    return sys.stdout.isatty()


def _clip(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _box(content_lines: Sequence[str], *, header: Optional[str] = None, double: bool = True) -> str:
    """Draws one box. ``content_lines`` are pre-formatted (already clipped to
    fit); ``header``, if given, gets its own centered line and a separator
    before the body."""
    h, v, tl, tr, bl, br, sep_l, sep_r, sep_m = (
        ("═", "║", "╔", "╗", "╚", "╝", "╠", "╣", "═") if double
        else ("─", "│", "┌", "┐", "└", "┘", "├", "┤", "─")
    )
    out = [tl + h * _INNER + tr]
    if header is not None:
        out.append(v + _clip(header, _INNER).center(_INNER) + v)
        if content_lines:
            out.append(sep_l + sep_m * _INNER + sep_r)
    for line in content_lines:
        out.append(v + " " + _clip(line, _INNER - 2).ljust(_INNER - 2) + " " + v)
    out.append(bl + h * _INNER + br)
    return "\n".join(out)


_LOGO = (
    "███╗   ███╗███████╗███╗   ███╗██████╗  ██████╗ ████████╗",
    "████╗ ████║██╔════╝████╗ ████║██╔══██╗██╔═══██╗╚══██╔══╝",
    "██╔████╔██║█████╗  ██╔████╔██║██████╔╝██║   ██║   ██║   ",
    "██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██╔══██╗██║   ██║   ██║   ",
    "██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║██║  ██║╚██████╔╝   ██║   ",
    "╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ",
)


def print_banner(version: str, subtitle: str) -> None:
    lines = [l.center(_INNER) for l in _LOGO] + [" " * _INNER, f"v{version} {subtitle}".center(_INNER)]
    top = "╔" + "═" * _INNER + "╗"
    bot = "╚" + "═" * _INNER + "╝"
    print(top)
    for l in lines:
        print("║" + l + "║")
    print(bot)


def print_panel(title: str, rows: Sequence[str]) -> None:
    print(_box(rows, header=title))


def print_footer(text: str) -> None:
    print(_box([], header=text))


def print_legend() -> None:
    print_panel("Status Legend", [
        "CONFIRMED     -- the attack reached its goal (canary/behavior observed)",
        "CLEAN         -- attempted, not reproduced this run (not proof of safety)",
        "ERROR         -- adapter/transport failure -- never silently counted as CLEAN",
        "INVALID       -- canary was already present before this variant ran (stale)",
        "NOT_EVALUATED -- this adapter cannot exercise this variant's delivery channel",
    ])


class ModelCheck:
    """One row of the "Validating models..." section: a label plus a
    zero-arg check callable returning (ok, detail). ``required=False`` means
    a failure here is reported but does not abort the run (e.g. an optional
    judge LLM that falls back to literal detection on its own)."""

    def __init__(self, label: str, check: Callable[[], Tuple[bool, str]], required: bool = True) -> None:
        self.label = label
        self.check = check
        self.required = required


def validate_models(checks: Sequence[ModelCheck]) -> bool:
    """Runs each check in order, printing a llamator-style checklist. Returns
    False only if a *required* check failed -- callers should abort the run
    in that case rather than proceed against an unreachable target."""
    print("Validating models...")
    all_required_ok = True
    for c in checks:
        try:
            ok, detail = c.check()
        except Exception as exc:  # noqa: BLE001 -- a validation check must never crash the CLI
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        mark = "✓" if ok else "✗"
        print(f"  {mark} {c.label}{' -- ' + detail if detail else ''}")
        if not ok and c.required:
            all_required_ok = False
    return all_required_ok


def print_audit_summary(ranked: Sequence, top_ids: Sequence[str], limitations: Sequence[str]) -> None:
    """The "our specifics" adaptation vs. llamator: audit stats before attack
    stats, because this project's premise is that a real audit's findings
    should drive attack selection, not the reverse."""
    by_sev: Dict[str, int] = {}
    for rf in ranked:
        sev = rf.severity or "UNKNOWN"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    sev_line = ", ".join(f"{sev}: {n}" for sev, n in sorted(by_sev.items(),
                         key=lambda kv: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(kv[0], 9)))
    rows = [f"{len(ranked)} FAIL finding(s) from the mcp_audit report, most severe first",
           f"By severity: {sev_line or 'n/a'}",
           f"Catalog re-ranked (not filtered) by severity -- top priority: {', '.join(top_ids[:5]) or 'n/a'}"]
    for lim in limitations:
        rows.append(f"note: {lim}")
    print_panel("Audit Summary", rows)


def make_progress(total: int, desc: str = "Attacking") -> Tuple[Callable, Callable[[], None]]:
    """Returns an ``(on_item, close)`` pair suited to a callback-shaped loop
    (``runner.engine.run_matrix``'s ``progress_hook``, or a plain manual
    ``for`` loop): call ``on_item(index, total, item, result)`` after each
    item finishes, ``close()`` once at the end. Uses a live tqdm bar when
    available, or a plain one-line-per-10% fallback otherwise -- the run must
    show progress either way, tqdm is a nicety, not a requirement (see module
    docstring)."""
    if total == 0:
        return (lambda *a, **k: None), (lambda: None)

    if _tqdm is not None:
        bar = _tqdm(total=total, desc=desc, unit="variant")

        def _on_item(index, _total, item, _result):
            label = getattr(item, "id", str(item))
            bar.set_description(f"{desc}: {label}")
            bar.update(1)

        return _on_item, bar.close

    state = {"last_pct": -1}

    def _on_item_plain(index, _total, item, _result):
        pct = int(((index + 1) / total) * 100)
        if pct != state["last_pct"] and pct % 10 == 0:
            print(f"{desc}: {pct}% ({index + 1}/{total})")
            state["last_pct"] = pct

    def _close_plain():
        if state["last_pct"] < 100:
            print(f"{desc}: 100% ({total}/{total})")

    return _on_item_plain, _close_plain


def _strength_bar(confirmed: int, total: int, bar_width: int = 14) -> str:
    if total == 0:
        return "[" + "-" * bar_width + "] n/a (0/0)"
    filled = round((confirmed / total) * bar_width)
    bar = "█" * filled + "-" * (bar_width - filled)
    pct = confirmed / total * 100
    return f"[{bar}] {confirmed}/{total} ({pct:.1f}%)"


def print_results_table(rows: Sequence[Tuple[str, int, int, int]], total_row: Tuple[str, int, int, int],
                        category_width: int = 30) -> None:
    """``rows``/``total_row`` are (label, confirmed, clean, excluded) tuples,
    ``excluded`` being ERROR+INVALID+NOT_EVALUATED combined (always shown,
    per this project's "never hide a non-CONFIRMED/CLEAN verdict" rule --
    just not folded into the ASR ratio itself, see ``models.py``). Column
    widths are computed from the actual content (headers included) rather
    than hardcoded, since the ASR bar's rendered width varies with the
    numbers involved."""
    headers = ("", "Category", "Confirmed", "Clean", "Err/Inv/N-E", "ASR (attack strength)")

    def build(label, confirmed, clean, excluded):
        mark = "✘" if confirmed > 0 else "✔"
        asr = _strength_bar(confirmed, confirmed + clean)
        return [mark, _clip(label, category_width), str(confirmed), str(clean), str(excluded), asr]

    body = [build(*r) for r in rows]
    total = build(*total_row)
    col_w = [max(len(headers[i]), *(len(r[i]) for r in body + [total])) + 2 for i in range(len(headers))]

    def fmt_cells(cells):
        return "│" + "│".join(f" {c:<{w - 1}}" for c, w in zip(cells, col_w)) + "│"

    def sep(l, m, r):
        return l + m.join("─" * w for w in col_w) + r

    print(sep("┌", "┬", "┐"))
    print(fmt_cells(headers))
    print(sep("├", "┼", "┤"))
    for r in body:
        print(fmt_cells(r))
    print(sep("├", "┼", "┤"))
    print(fmt_cells(total))
    print(sep("└", "┴", "┘"))
