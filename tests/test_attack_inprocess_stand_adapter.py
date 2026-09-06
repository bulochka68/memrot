"""Tests for mcp_attack.adapters.inprocess_stand.

``_StagingDDGS`` is tested standalone (no ``app`` import, always runs,
any Python version): it's the actual novel logic (single-shot staging with
fallback to the real search backend).

``InProcessStandAdapter`` itself imports the vendored ``app`` package, which
uses PEP 604 ``X | None`` unions as real runtime expressions in class/function
bodies (not just lazy type-hint strings) -- it requires Python 3.10+
independent of any package being installed. Those tests are skipped below
3.10 rather than attempted-and-failed, and even on 3.10+ only run if the
target's heavy dependencies (langchain/langgraph/etc, not part of this
project's own portable core) are actually installed.
"""
import sys

import pytest

from mcp_attack.adapters.inprocess_stand import _StagingDDGS


class _FakeRealDDGS:
    """Stands in for the real ddgs.DDGS class."""
    instances_created = 0

    def __init__(self):
        _FakeRealDDGS.instances_created += 1
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc_info):
        self.exited = True
        return False

    def text(self, query, max_results=5, **kwargs):
        return [{"title": "Real result", "href": "https://real.example/1", "body": f"real answer for {query}"}]


def setup_function(_):
    _FakeRealDDGS.instances_created = 0


def test_staged_content_is_returned_once_as_the_sole_result():
    staged = {"duckduckgo_search": "poisoned snippet with [CANARY-1]"}
    ddgs_factory = lambda: _StagingDDGS(staged, _FakeRealDDGS)   # mirrors functools.partial usage
    with ddgs_factory() as ddgs:
        results = ddgs.text("some query", max_results=5)
    assert len(results) == 1
    assert results[0]["body"] == "poisoned snippet with [CANARY-1]"
    assert _FakeRealDDGS.instances_created == 0   # never touched the real backend


def test_staged_content_is_consumed_single_shot_then_falls_back_to_real():
    staged = {"duckduckgo_search": "poisoned snippet"}
    with _StagingDDGS(staged, _FakeRealDDGS) as ddgs:
        first = ddgs.text("query one")
    assert first[0]["body"] == "poisoned snippet"
    assert "duckduckgo_search" not in staged   # consumed

    with _StagingDDGS(staged, _FakeRealDDGS) as ddgs:
        second = ddgs.text("query two")
    assert "real answer for query two" in second[0]["body"]
    assert _FakeRealDDGS.instances_created == 1


def test_no_staged_content_delegates_directly_to_real_ddgs():
    staged = {}
    with _StagingDDGS(staged, _FakeRealDDGS) as ddgs:
        results = ddgs.text("plain query")
    assert "real answer for plain query" in results[0]["body"]
    assert _FakeRealDDGS.instances_created == 1


def test_staging_only_affects_the_named_tool_key():
    """stage_tool_response is generic over tool_name; a wrapper for a
    DIFFERENT tool (e.g. a future email tool) would key off its own name --
    this confirms _StagingDDGS only ever looks at 'duckduckgo_search'."""
    staged = {"some_other_tool": "unrelated content"}
    with _StagingDDGS(staged, _FakeRealDDGS) as ddgs:
        results = ddgs.text("query")
    assert "real answer" in results[0]["body"]
    assert staged == {"some_other_tool": "unrelated content"}   # untouched


# --------------------------------------------------------------------------- #
# Full adapter -- only meaningful on Python 3.10+ with the target's heavy deps
# installed (langchain/langgraph/etc are not part of this project's own core
# dependencies, and app/config.py's `str | None` class-level annotations are
# real runtime expressions incompatible with Python <3.10).
# --------------------------------------------------------------------------- #

def _app_importable() -> bool:
    if sys.version_info < (3, 10):
        return False
    try:
        import app.agent.tools  # noqa: F401
    except Exception:
        return False
    return True


@pytest.mark.skipif(not _app_importable(), reason="requires Python 3.10+ and the vendored app/'s heavy deps installed")
def test_capabilities_reflect_white_box_grey_box_adapter():
    from mcp_attack.adapters.inprocess_stand import InProcessStandAdapter
    adapter = InProcessStandAdapter()
    caps = adapter.capabilities()
    assert caps.access_profile == "white_box"
    assert caps.supports_consolidate is True
    assert caps.supports_inspect_memory is True
    assert caps.supports_tool_staging is True


@pytest.mark.skipif(not _app_importable(), reason="requires Python 3.10+ and the vendored app/'s heavy deps installed")
def test_stage_tool_response_populates_staged_dict():
    from mcp_attack.adapters.inprocess_stand import InProcessStandAdapter
    adapter = InProcessStandAdapter()
    adapter.stage_tool_response("duckduckgo_search", "test content")
    assert adapter._staged.get("duckduckgo_search") == "test content"
