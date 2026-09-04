"""Layer 5 - Trifecta / Correlation engine.

Moves from tool-by-tool to a system verdict: is the lethal trifecta
assembled (sensitive access x untrusted input x external channel), can one
server shadow another, and what is the overall risk?
"""
from .trifecta import assess_trifecta
from .verdict import build_verdict, build_security_findings, build_summary

__all__ = ["assess_trifecta", "build_verdict", "build_security_findings", "build_summary"]
