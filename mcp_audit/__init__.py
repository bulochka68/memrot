"""Agent security audit subsystem (pipeline phase P1: Audit / Inventory).

Version 2.0 widens the object of the audit from "MCP tools" to the life
cycle of an agentic system: inventory and capabilities, definitions and
context, identity and authorization, memory, observed behaviour and
infrastructure.  MCP stays one of the supported interfaces.

Four version numbers are kept apart on purpose (TZ §2, §18):

* ``AUDIT_SCHEMA_VERSION`` - the JSON contract of the emitted report;
* ``RULESET_VERSION``      - the catalogue of control requirements;
* ``ENGINE_VERSION``       - this package (``__version__``);
* ``DOC_VERSION``          - the architecture document the code implements.

Every claim carries its own provenance, method, status, scope, confidence
and limitations.  There is no global ``verified`` flag and no fixed
confidence: the verdict is traceable to claims and evidence.
"""

__version__ = "2.0.0"
ENGINE_VERSION = __version__
AUDIT_SCHEMA = "agent-security-audit"
AUDIT_SCHEMA_VERSION = "2.0"
RULESET_VERSION = "2.0.0"
DOC_VERSION = "2.0"
LEGACY_SCHEMA_VERSIONS = ("1.0", "1.1")
