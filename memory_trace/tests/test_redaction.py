from __future__ import annotations

import hashlib

import pytest

from memory_trace.redaction import MODE_BASIC, SECRET_PLACEHOLDER, Redactor

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
SK = "sk-" + "A1b2C3d4E5" * 4
GHP = "ghp_" + "x" * 36
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
CANARY = "[H1-CCD9A7E7]"
CANARY_TOKEN = "CANARY_" + hashlib.sha256(CANARY.encode("utf-8")).hexdigest()[:16]


@pytest.mark.parametrize("kind, secret", [
    ("jwt", JWT), ("sk_token", SK), ("github_token", GHP), ("pem_private_key", PEM),
])
def test_secrets_are_replaced(no_presidio, kind, secret):
    result = Redactor().redact(f"token: {secret} end")

    assert secret not in result.text
    assert SECRET_PLACEHOLDER in result.text
    assert result.changed is True
    assert {"type": "secret", "kind": kind, "count": 1} in result.findings


@pytest.mark.parametrize("text, expected", [
    (f"{CANARY} в начале", f"{CANARY_TOKEN} в начале"),
    (f"метка {CANARY} в середине", f"метка {CANARY_TOKEN} в середине"),
])
def test_canary_is_replaced_with_hash_token(no_presidio, text, expected):
    result = Redactor().redact(text, canaries=[CANARY])

    assert result.text == expected
    assert result.changed is True
    assert any(f["type"] == "canary" and f["token"] == CANARY_TOKEN for f in result.findings)


def test_clean_text_is_unchanged(no_presidio):
    text = "обычная запись памяти без секретов"
    result = Redactor().redact(text)

    assert result.text == text
    assert result.changed is False
    assert result.mode == MODE_BASIC


def test_empty_presidio_url_falls_back_to_basic(monkeypatch, no_presidio):
    monkeypatch.setenv("PRESIDIO_API_URL", "")
    result = Redactor().redact(f"mail me at a@b.example, key {SK}")

    assert result.mode == MODE_BASIC
    assert SECRET_PLACEHOLDER in result.text
    assert "a@b.example" in result.text  # no PII level without Presidio
    assert any(f["type"] == "warning" for f in result.findings)
