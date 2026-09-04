"""MCP agent audit subsystem (pipeline phase P1: Audit / Inventory).

Three planes:
  * capability  - discovery + classification + effective access (layers 1, 3)
  * definition  - static analysis of tool descriptions / schemas (layer 2)
  * behavioral  - active probes in an isolated sandbox only (layer 4)

Every fact carries a provenance: ``declared`` (server self-report),
``effective`` (derived from config / permissions) or ``verified``
(confirmed by an active probe).  The verdict is built from
effective + verified facts only.
"""

__version__ = "1.1.0"
AUDIT_SCHEMA_VERSION = "1.1"
