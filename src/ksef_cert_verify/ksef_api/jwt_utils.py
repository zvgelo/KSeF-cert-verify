"""Wstępna inspekcja tokena JWT (accessToken KSeF).

UWAGA: dekodowanie JWT NIE dowodzi jego autentyczności – podpisu serwera nie weryfikujemy (nie mamy klucza).
Sprawdzamy wyłącznie strukturę i termin wygaśnięcia (`exp`), żeby odrzucić oczywiście błędny lub wygasły token
przed wysłaniem go do API. Token nigdy nie jest logowany ani zapisywany.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass
class JwtInfo:
    structure_ok: bool
    expired: bool | None = None
    expires_at: datetime | None = None
    error: str | None = None
    claims_present: list[str] = field(default_factory=list)  # tylko nazwy pól, bez wartości

    @property
    def usable(self) -> bool:
        return self.structure_ok and self.expired is False


def _decode_segment(seg: str) -> dict:
    data = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("segment JWT nie jest obiektem JSON")
    return obj


def inspect_jwt(token: str, now: datetime | None = None) -> JwtInfo:
    """Sprawdza strukturę (3 segmenty base64url, JSON w nagłówku i treści) oraz `exp`."""
    now = now or datetime.now(UTC)
    token = (token or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3 or not all(parts) or not all(_B64URL.match(p) for p in parts):
        return JwtInfo(
            False,
            error="To nie wygląda na token JWT (oczekiwano trzech segmentów base64url rozdzielonych kropkami).",
        )
    try:
        _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
    except (ValueError, json.JSONDecodeError):
        return JwtInfo(False, error="Nagłówek lub treść JWT nie jest poprawnym JSON-em w base64url.")
    exp = payload.get("exp")
    info = JwtInfo(True, claims_present=sorted(payload))
    if not isinstance(exp, (int, float)):
        info.error = "Token nie zawiera pola exp – nie można ocenić terminu ważności."
        return info
    info.expires_at = datetime.fromtimestamp(exp, UTC)
    info.expired = info.expires_at <= now
    if info.expired:
        info.error = f"Token JWT wygasł ({info.expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC)."
    return info


def describe(info: JwtInfo) -> str:
    base = "Struktura JWT poprawna; autentyczność NIE została potwierdzona (dekodowanie to nie weryfikacja)."
    if not info.structure_ok:
        return info.error or "Niepoprawny token JWT."
    if info.error:
        return info.error
    if info.expires_at is None:
        return base
    return f"{base} Ważny do {info.expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC."
