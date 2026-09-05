"""Compatibility shim: v1 ``default_probes`` -> v2 registered cases.

Kept so that existing imports keep working.  The cases still go through the
schema-agreement check in the runner; nothing is executed by guessing.
"""
from __future__ import annotations

from typing import List

from ..models import ServerRecord
from .fixtures import ControlCase, kind_cases

Probe = ControlCase


def default_probes(server: ServerRecord, canary_token: str, sinkhole: str) -> List[ControlCase]:
    return kind_cases(server, {"canary": canary_token, "sinkhole": sinkhole})
