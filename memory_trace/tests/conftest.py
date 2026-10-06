from __future__ import annotations

import sys

import pytest


@pytest.fixture
def no_presidio(monkeypatch):
    """Neither the analyzer API nor a local presidio_analyzer is available."""
    monkeypatch.delenv("PRESIDIO_API_URL", raising=False)
    monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
