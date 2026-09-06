"""Structural + semantic validation of the v2 report (TZ §15.1) and of the profile (P0-3)."""
from .schema import validate_document, ValidationError, SCHEMA_PATH
from .profile import (ProfileProblem, ProfileReport, lint_profile, profile_sources,
                      SCHEMA_PATH as PROFILE_SCHEMA_PATH)

__all__ = ["validate_document", "ValidationError", "SCHEMA_PATH",
           "lint_profile", "ProfileReport", "ProfileProblem", "profile_sources", "PROFILE_SCHEMA_PATH"]
