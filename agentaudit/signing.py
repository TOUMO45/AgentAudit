"""Tamper-evident signing for the JSON scorecard.

The signed JSON is what a CI gate consumes: it must be possible to prove the
report was produced by this tool and has not been edited after the fact. We use
HMAC-SHA256 over a canonical (sorted, whitespace-stable) serialization of the
scorecard with the ``signature`` field removed, plus a content digest.

Key resolution order:
  1. ``AGENTAUDIT_SIGNING_KEY`` environment variable (hex or utf-8), or
  2. an explicit key passed by the caller (used by tests), or
  3. a repo-local key auto-generated at ``.agentaudit/signing.key``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

_KEY_FILE = Path(".agentaudit/signing.key")


def _resolve_key(explicit: bytes | str | None) -> bytes:
    if explicit is not None:
        return explicit.encode() if isinstance(explicit, str) else explicit
    env = os.environ.get("AGENTAUDIT_SIGNING_KEY")
    if env:
        return env.encode()
    if _KEY_FILE.exists():
        return _KEY_FILE.read_text().strip().encode()
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    _KEY_FILE.write_text(key)
    return key.encode()


def _canonical(payload: dict[str, Any]) -> bytes:
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(payload: dict[str, Any], key: bytes | str | None = None) -> dict[str, Any]:
    """Return ``{alg, digest, hmac}`` for a scorecard dict."""
    k = _resolve_key(key)
    canonical = _canonical(payload)
    return {
        "alg": "HMAC-SHA256",
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "hmac": hmac.new(k, canonical, hashlib.sha256).hexdigest(),
    }


def verify(payload: dict[str, Any], key: bytes | str | None = None) -> bool:
    """True iff ``payload['signature']`` matches a fresh signature. Constant-time."""
    sig = payload.get("signature")
    if not isinstance(sig, dict) or "hmac" not in sig:
        return False
    expected = sign(payload, key)
    return hmac.compare_digest(expected["hmac"], sig["hmac"]) and hmac.compare_digest(
        expected["digest"], sig.get("digest", "")
    )
