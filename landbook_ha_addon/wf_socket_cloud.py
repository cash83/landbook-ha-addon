"""Cloud session manager for Wonderfree/Landbook smart sockets.

Deliberately SEPARATE from the powerstation LAN path. This module only talks to
the cloud REST API and owns two things the smart sockets need and the LAN side
does not:

  1. The access-token lifecycle (login + automatic re-login before expiry).
     The powerstation LAN key is a completely different credential and is NOT
     touched here.
  2. The live device list (userDeviceList), so sockets can be auto-detected,
     and sockets deleted from the app can be removed from Home Assistant.

Nothing in here imports or affects the LAN bridge loop; the bridge calls into
this module only from its smart-socket helpers.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import List, Optional

import requests

_CACHE_PATH = "/data/discovered.json"
_PLATFORMS_PATHS = (
    "/app/platforms.json",
    os.path.join(os.path.dirname(__file__), "platforms.json"),
)
_LOGIN_PATH = "/v2/enduser/enduserapi/emailPwdLogin"
_DEVICE_LIST_PATH = "/v2/binding/enduserapi/userDeviceList"
_TOKEN_SKEW = 600           # ri-login 10 min prima della scadenza
_FALLBACK_TOKEN_TTL = 7200  # se il server non dichiara la scadenza: ~2h


def _load_platforms() -> dict:
    try:
        from wf_autodiscovery import _PLATFORMS  # type: ignore
        if isinstance(_PLATFORMS, dict) and _PLATFORMS:
            return _PLATFORMS
    except Exception:
        pass
    for path in _PLATFORMS_PATHS:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return {}


def _jwt_exp(token: str) -> int:
    """Read the `exp` claim from a JWT access token, or 0 if not decodable."""
    try:
        import base64
        tok = str(token or "").strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        parts = tok.split(".")
        if len(parts) < 2:
            return 0
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", "replace"))
        exp = int(payload.get("exp") or 0)
        return exp if exp > 0 else 0
    except Exception:
        return 0


def _extract_exp(resp: dict) -> int:
    """Best-effort access-token expiry (epoch seconds)."""
    try:
        d = resp.get("data") or {}
        at = d.get("accessToken") or {}
        raw = at.get("expirationTime") if isinstance(at, dict) else None
        raw = raw or d.get("expirationTime") or 0
        val = float(raw)
        if val > 1e12:  # milliseconds
            val /= 1000.0
        if val > 0:
            return int(val)
    except Exception:
        pass
    return int(time.time()) + _FALLBACK_TOKEN_TTL


_SOCKET_PRODUCT_KEYS = {"p11spk"}


def extract_sockets(raw_devices: List[dict]) -> List[dict]:
    """Return the smart-socket subset of a userDeviceList response.

    Reuses wf_autodiscovery's parser when available so the two stay in sync.
    """
    try:
        from wf_autodiscovery import _extract_socket_devices  # type: ignore
        return _extract_socket_devices(raw_devices or [])
    except Exception:
        out: List[dict] = []
        seen = set()
        for dev in raw_devices or []:
            if not isinstance(dev, dict):
                continue
            dk = str(dev.get("deviceKey") or dev.get("device_key") or "").strip()
            pk = str(dev.get("productKey") or dev.get("product_key") or "").strip()
            if not dk or pk.lower() not in _SOCKET_PRODUCT_KEYS or dk in seen:
                continue
            seen.add(dk)
            out.append({
                "device_key": dk,
                "product_key": pk,
                "name": str(dev.get("deviceName") or dev.get("name") or dk),
                "product_name": str(dev.get("productName") or "Smart socket"),
                "online": bool(dev.get("onlineStatus", 0) or dev.get("status", 0)),
            })
        return out


class SocketCloud:
    """Owns the cloud access token and the live device list for smart sockets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.email = (os.environ.get("WF_EMAIL", "") or "").strip().lower()
        self.password = os.environ.get("WF_PASSWORD", "") or ""
        self.platform = (os.environ.get("PLATFORM", "") or "").strip().lower()

        cfg = _load_platforms().get(self.platform, {}) if self.platform else {}
        self.base_url = str(cfg.get("base_url") or os.environ.get("BASE_URL", "")).rstrip("/")
        self.secret_suffix = str(cfg.get("secret_suffix") or os.environ.get("SECRET_SUFFIX", ""))
        self.domain = str(cfg.get("wf_domain") or os.environ.get("WF_DOMAIN", ""))

        self.token = ""
        self.exp = 0  # 0 = scadenza sconosciuta → forza un login al primo uso
        # Riusa il token già scritto in cache all'avvio (evita un login se ancora
        # valido). Se è un JWT, ne leggiamo la scadenza reale dal claim `exp`.
        try:
            with open(_CACHE_PATH, "r", encoding="utf-8") as fh:
                self.token = str((json.load(fh) or {}).get("token") or "")
            if self.token:
                self.exp = _jwt_exp(self.token)
        except Exception:
            pass

    def available(self) -> bool:
        return bool(self.email and self.password and self.base_url
                    and self.secret_suffix and self.domain)

    # ── Token ────────────────────────────────────────────────────────────────
    def _login(self) -> str:
        from wf_autodiscovery import (  # type: ignore
            _login as _ad_login, _extract_token, _build_headers,
        )
        resp = _ad_login(
            self.base_url, _LOGIN_PATH, self.secret_suffix,
            self.email, self.password, self.domain, _build_headers(),
        )
        if not resp:
            raise RuntimeError("cloud login rifiutato")
        token = _extract_token(resp)
        if not token:
            raise RuntimeError("cloud login: token assente nella risposta")
        self.token = token
        # Preferisci la scadenza reale del JWT; altrimenti quella dichiarata
        # dalla risposta (con fallback ~2h).
        self.exp = _jwt_exp(token) or _extract_exp(resp)
        self._persist_token(token)
        remaining = self.exp - int(time.time())
        print(f"[socket-cloud] token cloud rinnovato (valido ~{remaining}s)", flush=True)
        return token

    def ensure_token(self, skew: int = _TOKEN_SKEW) -> str:
        """Return a valid bearer token, re-logging in when near expiry."""
        with self._lock:
            now = int(time.time())
            if self.token and self.exp and now < self.exp - skew:
                return self.token
            if not self.available():
                # Nessuna credenziale: possiamo solo riusare il token in cache.
                return self.token
            return self._login()

    def invalidate(self) -> None:
        with self._lock:
            self.exp = 0

    def _persist_token(self, token: str) -> None:
        """Rewrite only the token field of the shared discovered cache."""
        try:
            data = {}
            try:
                with open(_CACHE_PATH, "r", encoding="utf-8") as fh:
                    data = json.load(fh) or {}
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            data["token"] = token
            os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
            with open(_CACHE_PATH, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            print(f"[socket-cloud] persist token fallito: {exc}", flush=True)

    # ── Device list ────────────────────────────────────────────────────────────
    def list_devices(self) -> Optional[List[dict]]:
        """Raw userDeviceList items, or None on failure (keep current HA state)."""
        from wf_autodiscovery import _normalize_auth  # type: ignore
        for attempt in (1, 2):
            try:
                token = self.ensure_token()
            except Exception as exc:
                print(f"[socket-cloud] token non disponibile: {exc}", flush=True)
                return None
            if not token:
                return None
            try:
                r = requests.get(
                    self.base_url + _DEVICE_LIST_PATH,
                    params={"pageSize": 50, "isAssociated": 1},
                    headers={"Accept": "application/json",
                             "Authorization": _normalize_auth(token)},
                    timeout=8,
                )
                j = r.json()
            except Exception as exc:
                print(f"[socket-cloud] userDeviceList errore: {exc}", flush=True)
                return None
            code = j.get("code")
            if code == 200:
                data = j.get("data") or {}
                return (data.get("list") if isinstance(data, dict) else None) or []
            # Token rifiutato → invalida e riprova una sola volta.
            if attempt == 1 and (code in (401, 40100, 4010) or code == 10000):
                self.invalidate()
                continue
            print(f"[socket-cloud] userDeviceList code={code} msg={j.get('msg')}", flush=True)
            return None
        return None


_INSTANCE: Optional[SocketCloud] = None
_INSTANCE_LOCK = threading.Lock()


def get_cloud() -> Optional[SocketCloud]:
    global _INSTANCE
    if _INSTANCE is None:
        with _INSTANCE_LOCK:
            if _INSTANCE is None:
                try:
                    _INSTANCE = SocketCloud()
                except Exception as exc:
                    print(f"[socket-cloud] init fallita: {exc}", flush=True)
                    return None
    return _INSTANCE
