"""wf_autodiscovery.py - Auto-discovery generica per bridge Acceleronix

Con il campo 'platform' nel config, tutti i parametri tecnici
(base_url, accel_url, wf_domain, secret_suffix, realtime_attrs_url)
vengono impostati automaticamente.

Config minimo:
    wf_email, wf_password, platform, mqtt_host, mqtt_user, mqtt_pass

Parametri auto-scoperti (via API dopo login):
    device_key, product_key, accel_client

Fonte dati piattaforma: app_dokit_env.yml estratto dall'APK Quectel.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import string
import time
from typing import Any, Dict, List, Optional

import requests
from Crypto.Cipher import AES
from wf_privacy import mask_value

log = logging.getLogger("wf-autodiscovery")

_CACHE_PATH = "/data/discovered.json"
_CACHE_TTL  = 86400 * 30   # 30 giorni

# ── Catalogo piattaforme (da app_dokit_env.yml nell'APK) ─────────────────────
# Chiave: nome piattaforma (valore del campo 'platform' nel config)
# userDomainSecret = secret_suffix usato per firmare il login
_PLATFORMS: Dict[str, Dict[str, str]] = {}

# Platform catalog is loaded from platforms.json. Do not duplicate endpoints here.

def _load_platforms_from_file(defaults: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    path = os.path.join(os.path.dirname(__file__), "platforms.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        if not isinstance(data, dict):
            raise ValueError("platforms.json non contiene un oggetto JSON")
        required = {"base_url", "accel_url", "wf_domain", "secret_suffix", "realtime_attrs_url"}
        for name, cfg in data.items():
            if not isinstance(cfg, dict):
                raise ValueError(f"config piattaforma non valida: {name}")
            missing = sorted(required - set(cfg))
            if missing:
                raise ValueError(f"config piattaforma incompleta: {name} ({', '.join(missing)})")
        return {str(k): {str(ck): str(cv) for ck, cv in v.items()} for k, v in data.items()}
    except Exception as e:
        raise SystemExit(f"[AUTODISCOVERY] platforms.json non caricato o non valido: {e}") from e


_PLATFORMS = _load_platforms_from_file(_PLATFORMS)


def _rand(n: int = 16) -> str:
    a = string.ascii_letters + string.digits
    return "".join(random.choice(a) for _ in range(n))


def _pkcs7_pad(b: bytes, block: int = 16) -> bytes:
    pad = block - (len(b) % block)
    return b + bytes([pad]) * pad


def _make_pwd(password: str, rnd: str) -> str:
    md5hex = hashlib.md5(rnd.encode()).hexdigest()
    mid    = md5hex[8:24]
    key    = mid.upper().encode("ascii")
    iv     = (mid[8:16] + mid[0:8]).upper().encode("ascii")
    ct     = AES.new(key, AES.MODE_CBC, iv).encrypt(
                 _pkcs7_pad(password.encode(), 16))
    return base64.b64encode(ct).decode("ascii")


def _make_sig(email: str, pwd_b64: str, rnd: str, secret_suffix: str) -> str:
    s = f"{email}{pwd_b64}{rnd}{secret_suffix}"
    return hashlib.sha256(s.encode()).hexdigest()


def _normalize_auth(token: str) -> str:
    tok = token.strip()
    return tok if tok.lower().startswith("bearer ") else f"Bearer {tok}"

# ── Lettura config ────────────────────────────────────────────────────────────

def _read_options() -> dict:
    try:
        p = "/data/options.json"
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f) or {}
    except Exception:
        pass
    return {}


def _get(env_key: str, opts: dict, opt_key: str = "") -> str:
    v = os.getenv(env_key, "").strip()
    if v:
        return v
    k = opt_key or env_key.lower()
    return str(opts.get(k, "")).strip()

# ── Cache ─────────────────────────────────────────────────────────────────────

def _load_cache(current_platform: str = "") -> Optional[dict]:
    try:
        if not os.path.exists(_CACHE_PATH):
            return None
        with open(_CACHE_PATH, encoding="utf-8") as f:
            d = json.load(f)
        if int(time.time()) - int(d.get("_ts", 0)) > _CACHE_TTL:
            # La LAN key non scade mai (cambia solo con unbind/rebind).
            # Se è presente in cache, la usiamo indefinitamente e
            # lasciamo che il token venga rinnovato al prossimo avvio
            # con connettività internet.
            lan_key = d.get("lan_key_hex", "")
            if lan_key:
                log.info("[AUTODISCOVERY] Cache scaduta ma LAN key presente — uso cache senza scadenza")
            else:
                log.info("[AUTODISCOVERY] Cache scaduta e LAN key assente, rifaccio discovery")
                return None
        cached_platform = d.get("_platform", "")
        if current_platform and cached_platform and cached_platform != current_platform:
            log.warning(
                f"[AUTODISCOVERY] Piattaforma cambiata ({cached_platform} → {current_platform}), "
                "cache invalidata — riavvio discovery."
            )
            return None
        # Valida che il prefisso dell'accel_client corrisponda al dominio della piattaforma.
        # Esempio: piattaforma "wonderfree" (dominio E.SP...) richiede qu_E..., non qu_U... o qu_UE...
        if current_platform:
            plat_cfg = _PLATFORMS.get(current_platform, {})
            plat_domain = plat_cfg.get("wf_domain", "")
            if plat_domain and plat_domain[0].isalpha():
                expected_prefix = plat_domain[0].upper()
                cached_accel = d.get("accel_client", "")
                # Estrae il prefisso del client ID: "qu_E82519_" → 'E', "qu_UE82519_" → 'U'
                if cached_accel.startswith("qu_") and len(cached_accel) > 3 and cached_accel[3].isalpha():
                    actual_prefix = cached_accel[3]
                    if actual_prefix != expected_prefix:
                        log.warning(
                            f"[AUTODISCOVERY] Cache accel_client prefix '{actual_prefix}' != "
                            f"atteso '{expected_prefix}' (dominio {plat_domain}) — cache invalidata."
                        )
                        return None
        log.info("[AUTODISCOVERY] Valori caricati dalla cache")
        return d
    except Exception:
        return None


def _load_cache_stale(current_platform: str = "") -> Optional[dict]:
    """Carica la cache ignorando il TTL — usato come fallback offline."""
    try:
        if not os.path.exists(_CACHE_PATH):
            return None
        with open(_CACHE_PATH, encoding="utf-8") as f:
            d = json.load(f)
        # Ignora TTL ma controlla piattaforma
        cached_platform = d.get("_platform", "")
        if current_platform and cached_platform and cached_platform != current_platform:
            return None
        log.warning("[AUTODISCOVERY] Usando cache scaduta (modalità offline)")
        return d
    except Exception:
        return None


def _save_cache(data: dict, platform: str = "") -> None:
    try:
        data["_ts"] = int(time.time())
        if platform:
            data["_platform"] = platform
        dirn = os.path.dirname(_CACHE_PATH)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log.debug(f"[AUTODISCOVERY] Cache salvata in {_CACHE_PATH}")
    except Exception as e:
        log.warning(f"[AUTODISCOVERY] Impossibile salvare cache: {e}")

# ── Login ─────────────────────────────────────────────────────────────────────

def _build_headers(app_id: str = "584", app_version: str = "3.3.1") -> Dict[str, str]:
    return {
        "appVersion":    app_version,
        "appSystemType": "android",
        "appId":         app_id,
        "Accept":        "application/json",
        "Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
    }


def _login(base_url: str, login_path: str, secret_suffix: str,
           email: str, password: str, domain: str,
           headers: dict) -> Optional[dict]:
    rnd     = _rand(16)
    pwd_b64 = _make_pwd(password, rnd)
    sig     = _make_sig(email, pwd_b64, rnd, secret_suffix)
    data    = {
        "email": email, "pwd": pwd_b64,
        "random": rnd, "userDomain": domain, "signature": sig,
    }
    try:
        r = requests.post(
            base_url.rstrip("/") + login_path,
            data=data, headers=headers, timeout=15,
        )
        j = r.json()
        if j.get("code") == 200:
            return j
        log.warning(
            f"[AUTODISCOVERY] Login rifiutato dal server: code={j.get('code')} msg={j.get('msg', '')} "
            f"(url={base_url}, domain={domain})"
        )
    except Exception as e:
        log.warning(f"[AUTODISCOVERY] Login exception: {e}")
    return None


def _extract_token(resp: dict) -> str:
    d  = resp.get("data") or {}
    at = d.get("accessToken") or {}
    if isinstance(at, dict):
        return str(at.get("token") or "")
    return str(at or d.get("token") or "")


def _decode_jwt_uid(token_str: str) -> Optional[str]:
    try:
        tok = token_str.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        parts = tok.split(".")
        if len(parts) < 2:
            return None
        p = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p).decode())
        uid = payload.get("uid") or payload.get("userId")
        if uid and str(uid) != "subject":
            return str(uid)
    except Exception:
        pass
    return None


def _extract_user_id(resp: dict) -> Optional[str]:
    d = resp.get("data") or {}
    for tok_field in ("accessToken", "refreshToken"):
        tok_obj = d.get(tok_field) or {}
        tok_str = tok_obj.get("token") if isinstance(tok_obj, dict) else str(tok_obj or "")
        if tok_str:
            uid = _decode_jwt_uid(tok_str)
            if uid:
                return uid
    for key in ("userId", "uid", "id", "user_id"):
        v = d.get(key)
        if v:
            return str(v)
    return None


def _get_user_info(base_url: str, token: str, headers: dict) -> Optional[dict]:
    auth_h = {**headers, "Authorization": _normalize_auth(token)}
    try:
        r = requests.get(
            base_url.rstrip("/") + "/v2/enduser/enduserapi/userInfo",
            headers=auth_h, timeout=8,
        )
        j = r.json()
        if j.get("code") == 200:
            return j.get("data") or {}
    except Exception:
        pass
    return None

# ── Device list ───────────────────────────────────────────────────────────────

_BINDING_PATHS = [
    "/v2/binding/enduserapi/userDeviceList",
    "/v2/binding/enduserapi/getBindingList",
    "/v2/binding/enduserapi/getUserBindingList",
    "/v2/binding/enduserapi/getDeviceList",
]

_BINDING_PARAMS = [
    {"pageSize": 20, "isAssociated": 1},
    {"pageSize": 20, "isAssociated": "true"},
    {"pageSize": 20},
    {},
]

_LAN_KEY_PATHS = [
    "/v2/binding/enduserapi/getDeviceBusinessAttributes",
    "/v2/binding/enduserapi/getDeviceInfo",
    "/v2/binding/enduserapi/deviceInfo",
    "/v2/binding/enduserapi/getBindingDetail",
    "/v2/binding/enduserapi/getBindingInfo",
]


def _get_devices(base_url: str, token: str, headers: dict) -> List[dict]:
    auth_h = {**headers, "Authorization": _normalize_auth(token)}
    for path in _BINDING_PATHS:
        for params in _BINDING_PARAMS:
            try:
                r = requests.get(
                    base_url.rstrip("/") + path,
                    params=params, headers=auth_h, timeout=10,
                )
                j = r.json()
                log.debug(
                    f"[AUTODISCOVERY] {path} params={params} "
                    f"→ code={j.get('code')} data={type(j.get('data')).__name__}"
                )
                if j.get("code") == 200:
                    items: Any = j.get("data") or []
                    if isinstance(items, dict):
                        items = (
                            items.get("list")
                            or items.get("records")
                            or items.get("data")
                            or list(items.values())
                        )
                    if isinstance(items, list) and items:
                        devices = [
                            item for item in items
                            if isinstance(item, dict) and all(_parse_device(item))
                        ]
                        if devices:
                            log.debug(f"[AUTODISCOVERY] {len(devices)} dispositivi trovati → {path}")
                            # Log delle chiavi del primo dispositivo per debug LAN key
                            first = devices[0]
                            safe_keys = {k: (mask_value(str(v)) if k.lower() in ("authkey","bindingkey","authorizationkey","lankey","lan_key","key","password","token") else (str(v)[:60] if isinstance(v, str) else type(v).__name__)) for k, v in first.items()}
                            log.debug(f"[AUTODISCOVERY] Primo dispositivo chiavi: {safe_keys}")
                            return devices
                        log.debug(
                            f"[AUTODISCOVERY] {path} params={params} non contiene device validi "
                            f"({len(items)} elementi grezzi)"
                        )
            except Exception as e:
                log.debug(f"[AUTODISCOVERY] {path} errore: {e}")
    return []


def _parse_device(dev: Any) -> tuple[str, str]:
    if not isinstance(dev, dict):
        return "", ""
    dk = str(dev.get("deviceKey") or dev.get("dk") or dev.get("device_key") or "")
    pk = str(dev.get("productKey") or dev.get("pk") or dev.get("product_key") or "")
    return dk, pk


_POWERSTATION_PRODUCT_KEYS = {"p11tpn", "p11uve"}
_POWERSTATION_NAME_HINTS = ("fppt", "t2400", "powerstation", "power station", "portable energy")
_SOCKET_PRODUCT_KEYS = {"p11spk"}
_SOCKET_NAME_HINTS = ("socket", "plug", "presa")


def _extract_socket_devices(devices: List[dict]) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for dev in devices or []:
        dk, pk = _parse_device(dev)
        pk_l = str(pk or "").strip().lower()
        if pk_l not in _SOCKET_PRODUCT_KEYS:
            continue
        if dk in seen:
            continue
        seen.add(dk)
        out.append({
            "device_key": dk,
            "product_key": pk,
            "name": str(dev.get("deviceName") or dev.get("name") or dk),
            "product_name": str(dev.get("productName") or "Smart socket"),
            "online": bool(dev.get("onlineStatus", 0) or dev.get("status", 0)),
            "signal_strength": dev.get("signalStrength"),
        })
    return out


def _device_selection_score(dev: dict) -> int:
    dk, pk = _parse_device(dev)
    pk_l = str(pk or "").strip().lower()
    name_l = str(dev.get("deviceName") or dev.get("name") or "").strip().lower()
    score = 0
    if pk_l in _POWERSTATION_PRODUCT_KEYS:
        score += 100
    if any(hint in name_l for hint in _POWERSTATION_NAME_HINTS):
        score += 30
    if pk_l in _SOCKET_PRODUCT_KEYS:
        score -= 100
    if any(hint in name_l for hint in _SOCKET_NAME_HINTS):
        score -= 30
    if dk:
        score += 1
    return score


def _select_default_device(devices: List[dict]) -> dict:
    if not devices:
        return {}
    ranked = sorted(
        enumerate(devices),
        key=lambda item: (_device_selection_score(item[1]), -item[0]),
        reverse=True,
    )
    return ranked[0][1]


def _parse_tsl_controls(raw: Any) -> Dict[str, dict]:
    if isinstance(raw, dict):
        data = raw.get("data", raw)
        if isinstance(data, dict) and "tsl" in data:
            data = data.get("tsl")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
    elif isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
    else:
        data = raw

    props = []
    if isinstance(data, dict):
        props = (
            data.get("properties")
            or data.get("property")
            or data.get("customizeTslInfo")
            or data.get("tslInfo")
            or data.get("businessAttributes")
            or data.get("attributes")
            or data.get("functions")
            or data.get("function")
            or []
        )
    elif isinstance(data, list):
        props = data

    controls: Dict[str, dict] = {}

    def _current_value(item: dict):
        for key in ("resourceValce", "resourceValue", "attributeValue", "value", "paramValue"):
            value = item.get(key)
            if value not in (None, ""):
                return value
        return None

    for item in props:
        if not isinstance(item, dict):
            continue
        code = str(
            item.get("code")
            or item.get("resourceCode")
            or item.get("attributeCode")
            or item.get("attrCode")
            or item.get("identifier")
            or item.get("identifierName")
            or item.get("name")
            or ""
        ).strip()
        control_id = (
            item.get("id", item.get("abId", item.get("abid")))
            or item.get("resourceId")
            or item.get("attributeId")
            or item.get("attrId")
            or item.get("paramId")
        )
        if not code or control_id is None:
            continue
        data_type = str(
            item.get("dataType")
            or item.get("type")
            or item.get("valueType")
            or ""
        ).upper()
        access = str(item.get("subType") or item.get("rwFlag") or item.get("access") or item.get("accessMode") or "").upper()
        controls[code] = {
            "id": int(control_id),
            "code": code,
            "name": item.get("name") or item.get("title") or code,
            "type": data_type,
            "access": access,
            "writable": access in ("W", "RW", "WRITE", "READWRITE"),
            "specs": item.get("specs") or item.get("define") or item.get("schema") or {},
            "current_value": _current_value(item),
        }
    return controls


TSL_DUMP_PATH = "/data/landbook_tsl.json"
TSL_SHARE_DUMP_PATH = "/share/landbook_tsl.json"

# Bump whenever the parser shape changes — addon_run.py uses this to detect a
# stale TSL dump written by a previous addon version and force a cloud refresh.
TSL_PARSER_VERSION = 7


def _parse_tsl_properties(raw: Any) -> Dict[str, dict]:
    """Parse the full TSL property/function tree, preserving nested struct sub-fields.

    Unlike _parse_tsl_controls (which keeps only id+type for command building), this
    walks specs/define recursively so the TTLV sensor walker can know the layout of
    struct properties like pv_data, ac_data, bms_cell_data, etc."""

    def _unwrap(node: Any) -> Any:
        if isinstance(node, dict) and "data" in node:
            node = node.get("data", node)
        if isinstance(node, dict) and "tsl" in node:
            node = node.get("tsl")
        if isinstance(node, str):
            try:
                return json.loads(node)
            except Exception:
                return {}
        return node

    data = _unwrap(raw)
    items: list = []
    if isinstance(data, dict):
        for key in ("properties", "property", "customizeTslInfo", "tslInfo",
                    "businessAttributes", "attributes", "functions", "function",
                    "events", "event"):
            v = data.get(key)
            if isinstance(v, list):
                items.extend(v)
    elif isinstance(data, list):
        items = data

    # Field-name candidates — Aliyun/Quectel TSLs use inconsistent naming across
    # endpoints. We try them all rather than guessing per endpoint.
    CODE_KEYS  = ("code", "resourceCode", "attributeCode", "attrCode",
                  "identifier", "identifierName", "paramCode", "name")
    ID_KEYS    = ("id", "abId", "abid", "resourceId", "attributeId", "attrId", "paramId", "fieldId", "tagId")
    TYPE_KEYS  = ("dataType", "type", "valueType", "paramType")
    SPECS_KEYS = ("specs", "define", "schema", "specsList", "specsValue")
    SUB_KEYS   = ("subAttributes", "subItems", "subFields", "children",
                  "params", "paramList", "attrItems", "fields", "items", "sub")
    ACCESS_KEYS = ("subType", "rwFlag", "access", "accessMode", "readWrite")

    def _maybe_json(value: Any) -> Any:
        """resourceValue / value fields are sometimes JSON-encoded strings carrying
        the actual struct definition. Decode opportunistically."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    return json.loads(stripped)
                except Exception:
                    return value
        return value

    def _first(item: dict, keys: tuple) -> Any:
        for k in keys:
            v = item.get(k)
            if v not in (None, "", []):
                return v
        return None

    def _norm_type(item: dict) -> tuple:
        """Return (type_str, specs) where type_str is upper-case and specs is
        the raw specs value (list, dict, or None — caller decides shape)."""
        dt = _first(item, TYPE_KEYS) or ""
        specs = None
        if isinstance(dt, dict):
            specs = _first(dt, SPECS_KEYS)
            dt = dt.get("type") or dt.get("dataType") or ""
        if specs is None:
            specs = _first(item, SPECS_KEYS)
        return str(dt).upper(), specs

    def _extract_sub_list(item: dict, specs: Any) -> list:
        """Find sub-field list under any of several conventions.

        Aliyun TSL shapes observed:
          STRUCT → `specs` is a list of sub-fields (PV, Grid, Battery, AC, DC…).
          ARRAY  → `specs` is `{size, dataType:"STRUCT", specs:[sub-fields]}`
                   (bms_celldata_no, pack_data, timed_*) — one level of nesting.
        """
        # 1. specs itself is a list of sub-fields
        if isinstance(specs, list):
            return specs
        # 2. specs dict has either an explicit sub-key OR a nested specs list
        # (the ARRAY shape uses the latter, with no sub-key).
        if isinstance(specs, dict):
            nested = specs.get("specs")
            if isinstance(nested, list) and nested:
                return nested
            for k in SUB_KEYS:
                v = specs.get(k)
                if isinstance(v, list) and v:
                    return v
        # 3. item itself has a sub-list field (parallel to specs)
        for k in SUB_KEYS:
            v = item.get(k)
            if isinstance(v, list) and v:
                return v
            if isinstance(v, str):
                decoded = _maybe_json(v)
                if isinstance(decoded, list) and decoded:
                    return decoded
        # 4. resource-style item with a JSON-encoded value field
        for k in ("resourceValue", "value", "paramValue"):
            decoded = _maybe_json(item.get(k))
            if isinstance(decoded, list) and decoded:
                return decoded
            if isinstance(decoded, dict):
                for sk in SUB_KEYS:
                    v = decoded.get(sk)
                    if isinstance(v, list) and v:
                        return v
        return []

    def _parse_item(item: dict) -> dict:
        code = str(_first(item, CODE_KEYS) or "").strip()
        ident = _first(item, ID_KEYS)
        type_str, specs = _norm_type(item)
        access = str(_first(item, ACCESS_KEYS) or "").upper()
        entry = {
            "id":       int(ident) if ident is not None else None,
            "code":     code,
            "name":     item.get("name") or item.get("title") or code,
            "type":     type_str,
            "access":   access,
            "writable": access in ("W", "RW", "WRITE", "READWRITE"),
            # Keep specs as-is even when it's a list: ENUM properties store their
            # value→label options as a list and the discovery layer needs that
            # to build HA select entities. Struct sub-fields are handled
            # separately through `children` below.
            "specs":    specs,
            "current_value": item.get("resourceValce", item.get("resourceValue", item.get("attributeValue", item.get("value", item.get("paramValue"))))),
        }
        children = {}
        for sf in _extract_sub_list(item, specs):
            if not isinstance(sf, dict):
                continue
            parsed = _parse_item(sf)
            if parsed.get("code") and parsed.get("id") is not None:
                children[parsed["code"]] = parsed
        if children:
            entry["children"] = children
        return entry

    out: Dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        parsed = _parse_item(item)
        if parsed.get("code") and parsed.get("id") is not None:
            out[parsed["code"]] = parsed
    return out


def _dump_tsl_to_data(raw_responses: list, controls: Dict[str, dict],
                      properties: Dict[str, dict], product_key: str) -> None:
    """Persist the full TSL snapshot to /data so the bridge can build the sensor
    walker schema without re-contacting the cloud at startup."""
    bundle = {
        "parser_version": TSL_PARSER_VERSION,
        "product_key":    product_key,
        "fetched_at":     int(time.time()),
        "controls":       controls,
        "properties":     properties,
        "raw_responses":  raw_responses,
    }
    try:
        os.makedirs(os.path.dirname(TSL_DUMP_PATH), exist_ok=True)
        with open(TSL_DUMP_PATH, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False)
        log.info(f"[AUTODISCOVERY] TSL dump scritto in {TSL_DUMP_PATH} "
                 f"(controls={len(controls)} properties={len(properties)} raw={len(raw_responses)})")

        # Copia consultabile dall'utente in /share. Il bridge continua a usare
        # /data per il runtime, ma ogni nuovo TSL viene salvato anche qui.
        try:
            os.makedirs(os.path.dirname(TSL_SHARE_DUMP_PATH), exist_ok=True)
            with open(TSL_SHARE_DUMP_PATH, "w", encoding="utf-8") as f:
                json.dump(bundle, f, ensure_ascii=False, indent=2)
            log.info(f"[AUTODISCOVERY] Copia TSL salvata in {TSL_SHARE_DUMP_PATH}")
        except OSError as e:
            log.warning(f"[AUTODISCOVERY] TSL share dump write failed: {e}")
    except OSError as e:
        log.warning(f"[AUTODISCOVERY] TSL dump write failed: {e}")


def _try_fetch_tsl_controls(base_url: str, token: str, headers: dict, product_key: str, device_key: str = "") -> Dict[str, dict]:
    if not product_key:
        return {}
    auth_h = {**headers, "Authorization": _normalize_auth(token)}
    requests_to_try = [
        ("/v2/binding/enduserapi/productTSL", {"pk": product_key}),
        ("/v2/binding/enduserapi/productTSL", {"productKey": product_key}),
        ("/v2/binding/enduserapi/getProductTSL", {"pk": product_key}),
        ("/v2/binding/enduserapi/getProductTSL", {"productKey": product_key}),
    ]
    if device_key:
        requests_to_try.extend([
            ("/v2/binding/enduserapi/getDeviceBusinessAttributes", {"dk": device_key, "pk": product_key}),
            ("/v2/binding/enduserapi/getDeviceBusinessAttributes", {"deviceKey": device_key, "productKey": product_key}),
        ])
    merged_controls: Dict[str, dict] = {}
    merged_properties: Dict[str, dict] = {}
    raw_responses: list = []
    for path, params in requests_to_try:
        try:
            r = requests.get(base_url.rstrip("/") + path, params=params, headers=auth_h, timeout=10)
            j = r.json()
            if j.get("code") not in (0, 200, "0", "200", None):
                log.debug(f"[AUTODISCOVERY] {path} params={params} code={j.get('code')}")
                continue
            raw_responses.append({"endpoint": path, "params": params, "response": j})
            controls = _parse_tsl_controls(j)
            properties = _parse_tsl_properties(j)
            # Smart merge: NEVER replace a richer entry with a poorer one.
            # productTSL returns full schema (specs list, enum options, struct
            # sub-fields). getDeviceBusinessAttributes returns only current
            # *values* — its entries lack specs/children. The previous logic
            # blindly used dict.update(), so the values-only entries overwrote
            # the schema-rich ones and HA selects ended up empty.
            def _is_richer(new_e: dict, old_e: dict) -> bool:
                if not old_e:
                    return True
                old_specs = old_e.get("specs")
                new_specs = new_e.get("specs")
                # any new entry with specs wins over one without
                if new_specs and not old_specs:
                    return True
                # children present wins
                if new_e.get("children") and not old_e.get("children"):
                    return True
                # otherwise keep the existing
                return False

            if controls:
                added = 0
                for k, v in controls.items():
                    existing = merged_controls.get(k) or {}
                    if _is_richer(v, existing):
                        merged_controls[k] = v
                        added += 1
                    elif v.get("current_value") not in (None, "") and existing.get("current_value") in (None, ""):
                        existing["current_value"] = v.get("current_value")
                log.info(f"[AUTODISCOVERY] TSL controls via {path}: {len(controls)} parsed, {added} richer kept")
            if properties:
                added = 0
                for k, v in properties.items():
                    existing = merged_properties.get(k) or {}
                    if _is_richer(v, existing):
                        merged_properties[k] = v
                        added += 1
                    elif v.get("current_value") not in (None, "") and existing.get("current_value") in (None, ""):
                        existing["current_value"] = v.get("current_value")
                log.info(f"[AUTODISCOVERY] TSL properties via {path}: {len(properties)} parsed, {added} richer kept")
        except Exception as e:
            log.debug(f"[AUTODISCOVERY] {path} errore TSL: {e}")
    if raw_responses:
        _dump_tsl_to_data(raw_responses, merged_controls, merged_properties, product_key)
    if merged_controls:
        log.info(f"[AUTODISCOVERY] TSL controls cached: {len(merged_controls)}")
        return merged_controls
    return {}

# ── Applica valori a os.environ ───────────────────────────────────────────────

def _setenv(key: str, val: str) -> None:
    """Imposta env var solo se non già presente."""
    if val and not os.getenv(key, "").strip():
        os.environ[key] = val


def _apply_platform(plat: dict) -> None:
    _setenv("BASE_URL",           plat.get("base_url", ""))
    _setenv("ACCEL_URL",          plat.get("accel_url", ""))
    _setenv("WF_DOMAIN",          plat.get("wf_domain", ""))
    _setenv("SECRET_SUFFIX",      plat.get("secret_suffix", ""))
    _setenv("REALTIME_ATTRS_URL", plat.get("realtime_attrs_url", ""))


def _apply_discovered(data: dict) -> None:
    for k, env_k in {
        "wf_domain":    "WF_DOMAIN",
        "device_key":   "DEVICE_KEY",
        "product_key":  "PRODUCT_KEY",
        "accel_client": "ACCEL_CLIENT",
        "lan_key_hex":  "LAN_KEY_HEX",
    }.items():
        v = data.get(k, "")
        if v:
            _setenv(env_k, v)
            if os.getenv(env_k) == v:
                log.debug(f"[AUTODISCOVERY] {env_k} = {mask_value(v)}")


def _normalize_lan_key(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip().replace(" ", "")
    if not s:
        return ""
    # 1) already-hex format
    if len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
            if len(raw) in (16, 24, 32):
                return s.lower()
        except Exception:
            pass
    # 2) base64 format (common for authKey in userDeviceList)
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) in (16, 24, 32):
            return raw.hex()
    except Exception:
        pass
    return ""


def _extract_lan_key_hex(dev: Any) -> str:
    if not isinstance(dev, dict):
        return ""
    for key in ("authKey", "authkey", "bindingkey", "bindingKey"):
        normalized = _normalize_lan_key(dev.get(key))
        if normalized:
            return normalized
    return ""


def _deep_find_lan_key_hex(obj: Any) -> str:
    if isinstance(obj, dict):
        direct = _extract_lan_key_hex(obj)
        if direct:
            return direct
        for v in obj.values():
            found = _deep_find_lan_key_hex(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _deep_find_lan_key_hex(v)
            if found:
                return found
    return ""


def _try_fetch_lan_key_from_cloud(
    base_url: str,
    token: str,
    headers: dict,
    device_key: str,
    product_key: str,
) -> str:
    auth_h = {**headers, "Authorization": _normalize_auth(token)}
    params_candidates = [
        {"dk": device_key, "pk": product_key},
        {"deviceKey": device_key, "productKey": product_key},
        {"deviceKey": device_key},
        {"dk": device_key},
        {"pk": product_key},
        {},
    ]
    for path in _LAN_KEY_PATHS:
        for params in params_candidates:
            try:
                r = requests.get(base_url.rstrip("/") + path, params=params, headers=auth_h, timeout=10)
                j = r.json()
                if j.get("code") != 200:
                    continue
                found = _deep_find_lan_key_hex(j.get("data"))
                if found:
                    log.info(f"[AUTODISCOVERY] LAN key trovata via {path}")
                    return found
                # Log chiavi disponibili per debug
                data = j.get("data")
                if isinstance(data, dict):
                    candidate_keys = {k: (str(v)[:40] if isinstance(v, str) else type(v).__name__) for k, v in data.items()}
                    log.warning(f"[AUTODISCOVERY] {path} risposta OK ma LAN key non trovata. data keys: {candidate_keys}")
            except Exception:
                continue
    return ""

# ── Entry point ───────────────────────────────────────────────────────────────

def setup(force: bool = False) -> None:
    """
    Chiamare da bridge.py PRIMA di importare wf_config.

    Con 'platform' nel config, imposta automaticamente:
      base_url, accel_url, wf_domain, secret_suffix, realtime_attrs_url

    Poi scopre automaticamente:
      device_key, product_key, accel_client

    Config minimo richiesto:
      wf_email, wf_password, platform (o tutti i parametri manuali)
    """
    opts = _read_options()

    # ── Credenziali ───────────────────────────────────────────────────────
    email    = _get("WF_EMAIL",    opts, "wf_email").lower()
    password = _get("WF_PASSWORD", opts, "wf_password")

    if not email or not password:
        raise SystemExit("[AUTODISCOVERY] wf_email e wf_password sono obbligatori.")

    # ── Selezione piattaforma ─────────────────────────────────────────────
    platform = _get("PLATFORM", opts, "app").lower().strip()

    if platform and platform != "custom":
        plat_cfg = _PLATFORMS.get(platform)
        if plat_cfg is None:
            available = ", ".join(sorted(_PLATFORMS.keys()))
            raise SystemExit(
                f"[AUTODISCOVERY] App '{platform}' non riconosciuta.\n"
                f"Valori disponibili: {available}\n"
                f"Oppure usa 'custom' e inserisci i parametri manualmente."
            )
        log.debug(f"[AUTODISCOVERY] App: {platform} → {plat_cfg['base_url']}")
        _apply_platform(plat_cfg)
    else:
        # Modalità custom: i parametri devono essere tutti nel config
        if not _get("BASE_URL",      opts, "base_url"):
            raise SystemExit("[AUTODISCOVERY] 'base_url' obbligatorio in modalità custom.")
        if not _get("SECRET_SUFFIX", opts, "secret_suffix"):
            raise SystemExit("[AUTODISCOVERY] 'secret_suffix' obbligatorio in modalità custom.")
        if not _get("ACCEL_URL",     opts, "accel_url"):
            raise SystemExit("[AUTODISCOVERY] 'accel_url' obbligatorio in modalità custom.")
        if not _get("REALTIME_ATTRS_URL", opts, "realtime_attrs_url"):
            raise SystemExit("[AUTODISCOVERY] 'realtime_attrs_url' obbligatorio in modalità custom.")
        if not _get("WF_DOMAIN",     opts, "wf_domain"):
            raise SystemExit("[AUTODISCOVERY] 'wf_domain' obbligatorio in modalità custom.")
        log.info("[AUTODISCOVERY] Modalità custom — uso parametri dal config.")

    # Leggi i valori ora (dopo aver applicato la piattaforma)
    base_url      = os.getenv("BASE_URL", "").strip() or _get("BASE_URL", opts, "base_url")
    secret_suffix = os.getenv("SECRET_SUFFIX", "").strip() or _get("SECRET_SUFFIX", opts, "secret_suffix")
    login_path    = _get("LOGIN_PATH", opts, "login_path") or "/v2/enduser/enduserapi/emailPwdLogin"
    app_id        = _get("APP_ID",     opts, "app_id")     or "584"
    app_version   = _get("APP_VERSION", opts, "app_version") or "3.3.1"
    headers       = _build_headers(app_id, app_version)

    # ── Verifica se config già completo ───────────────────────────────────
    domain      = _get("WF_DOMAIN",    opts, "wf_domain")  or os.getenv("WF_DOMAIN", "")
    device_key  = _get("DEVICE_KEY",   opts, "device_key")
    product_key = _get("PRODUCT_KEY",  opts, "product_key")
    accel_cli   = _get("ACCEL_CLIENT", opts, "accel_client")
    preferred_device_key = _get("DEVICE_KEY", opts, "device_key")
    lan_key_hex = _get("LAN_KEY_HEX", opts, "lan_login_key")
    want_lan_auto = True

    if domain and device_key and product_key and accel_cli and (lan_key_hex or not want_lan_auto):
        log.info("[AUTODISCOVERY] Config completo — skip discovery.")
        return

    # ── Carica dalla cache ────────────────────────────────────────────────
    if not force:
        cached = _load_cache(platform)
        if cached:
            cached_lan = _normalize_lan_key(cached.get("lan_key_hex", ""))
            if want_lan_auto and not lan_key_hex and not cached_lan:
                log.info("[AUTODISCOVERY] Cache trovata ma LAN key assente: rifaccio discovery")
            else:
                _apply_discovered(cached)
                if os.getenv("LAN_KEY_HEX", "").strip():
                    log.info("[AUTODISCOVERY] LAN_KEY_HEX loaded from cache")
                # Ripristina token dalla cache
                cached_token = cached.get("token", "")
                if cached_token:
                    os.environ["WF_TOKEN"] = cached_token
                return

    log.info("[AUTODISCOVERY] *** Avvio auto-discovery ***")

    domain = domain or os.getenv("WF_DOMAIN", "")
    if not domain:
        raise SystemExit(
            "[AUTODISCOVERY] wf_domain non trovato.\n"
            "Imposta 'app' nel config oppure specifica 'wf_domain' manualmente."
        )

    # ── Login ─────────────────────────────────────────────────────────────
    log.info(f"[AUTODISCOVERY] Login → {base_url}  domain={domain}")
    resp = _login(base_url, login_path, secret_suffix, email, password, domain, headers)
    if not resp:
        hint = ""
        if platform in ("wonderfree", "europe"):
            hint = (
                "\n  → Stai usando la piattaforma EUROPEA (acceleronix.io)."
                "\n  → Se il tuo dispositivo è Landecia/Landbook usa 'landecia' o 'landbook' nel campo 'app'."
            )
        elif platform in ("landbook", "landecia", "northamerica"):
            hint = (
                "\n  → Stai usando la piattaforma NORD AMERICA (netprisma.us/landecia.com)."
                "\n  → Se il tuo dispositivo è Wonderfree Europe usa 'wonderfree' o 'europe' nel campo 'app'."
            )
        stale = _load_cache_stale(platform)
        if stale:
            log.warning(
                "[AUTODISCOVERY] Login fallito ma cache disponibile — "
                "avvio in modalità offline con dati della cache."
            )
            _apply_discovered(stale)
            cached_token = stale.get("token", "")
            if cached_token:
                os.environ["WF_TOKEN"] = cached_token
            return
        raise SystemExit(
            f"[AUTODISCOVERY] Login fallito su {base_url} (domain={domain}).{hint}\n"
            "Controlla: wf_email, wf_password, app (o base_url/secret_suffix/wf_domain)"
        )

    token   = _extract_token(resp)
    user_id = _extract_user_id(resp)
    # Esporta il token per eventuali diagnostiche/fallback cloud durante setup.
    if token:
        os.environ["WF_TOKEN"] = token

    # ── userInfo post-login ───────────────────────────────────────────────
    log.info("[AUTODISCOVERY] Chiamo /userInfo...")
    user_info = _get_user_info(base_url, token, headers)
    if user_info:
        uid = user_info.get("uid") or user_info.get("userId") or user_info.get("id")
        if uid:
            user_id = str(uid)
            log.info(f"[AUTODISCOVERY] uid = {user_id}")

    # ── accel_client ──────────────────────────────────────────────────────
    if not accel_cli:
        if user_id:
            uid_str = str(user_id)
            # Il prefisso dell'accel_client segue il prefisso del wf_domain:
            #   E.SP.4294967410 → E  (Europe/Acceleronix)
            #   U.SP.8589934603 → U  (North America/Netprisma)
            #   C.DM.5903.1     → C  (China/Quectel)
            # Se l'ID ha già un prefisso letterale, lo preserva.
            # Se è numerico, aggiunge il prefisso derivato dal dominio.
            if uid_str and uid_str[0].isdigit():
                domain_prefix = domain[0].upper() if domain and domain[0].isalpha() else "U"
                prefix = f"{domain_prefix}{uid_str}"
            else:
                prefix = uid_str
            accel_cli = f"qu_{prefix}_"
            log.info(f"[AUTODISCOVERY] accel_client = {mask_value(accel_cli)}  (domain_prefix={domain[0] if domain else '?'})")
        else:
            raise SystemExit(
                "[AUTODISCOVERY] userId non trovato.\n"
                "Aggiungi 'accel_client' nel config (es: qu_U24701_)."
            )

    # ── Device list ───────────────────────────────────────────────────────
    selected_device: Optional[dict] = None
    devices: List[dict] = []
    if not device_key or not product_key or (want_lan_auto and not lan_key_hex):
        log.info("[AUTODISCOVERY] Cerco dispositivi...")
        devices = _get_devices(base_url, token, headers)

        if not devices:
            raise SystemExit(
                "[AUTODISCOVERY] Nessun dispositivo trovato.\n"
                "Aggiungi device_key e product_key nel config manualmente."
            )

        if len(devices) > 1:
            log.info(f"[AUTODISCOVERY] {len(devices)} dispositivi trovati:")
            for i, d in enumerate(devices):
                dk, pk = _parse_device(d)
                log.info(f"  [{i}] dk={mask_value(dk)}  pk={mask_value(pk)}  name={d.get('deviceName','?')}")

        selected_device = _select_default_device(devices)
        if selected_device is not devices[0]:
            dk, pk = _parse_device(selected_device)
            log.info(
                f"[AUTODISCOVERY] Uso dispositivo powerstation: "
                f"dk={mask_value(dk)} pk={mask_value(pk)} "
                f"name={selected_device.get('deviceName','?')}"
            )
        if preferred_device_key:
            preferred = str(preferred_device_key).strip()
            for d in devices:
                dk, _pk = _parse_device(d)
                if str(dk).strip() == preferred:
                    selected_device = d
                    log.info(f"[AUTODISCOVERY] Uso dispositivo configurato: {mask_value(dk)}")
                    break
            else:
                raise SystemExit(
                    "[AUTODISCOVERY] device_key configurato non trovato tra i dispositivi dell'account.\n"
                    "Controlla il valore oppure lascialo vuoto per usare il primo dispositivo."
                )

        if not device_key or not product_key:
            dk, pk = _parse_device(selected_device)
            if not dk or not pk:
                raise SystemExit(
                    f"[AUTODISCOVERY] Struttura dispositivo inattesa: {selected_device}\n"
                    "Aggiungi device_key e product_key nel config manualmente."
                )
            device_key, product_key = dk, pk
            log.info(f"[AUTODISCOVERY] device_key={mask_value(device_key)}  product_key={mask_value(product_key)}")

        if want_lan_auto and not lan_key_hex:
            lan_key_hex = _extract_lan_key_hex(selected_device)
            if lan_key_hex:
                log.info("[AUTODISCOVERY] LAN key discovered from binding metadata")
            else:
                # Mostra le chiavi disponibili nel device per aiutare il debug
                candidate_keys = [k for k in selected_device.keys() if any(hint in k.lower() for hint in ("auth","key","bind","lan","local","secret","token","pass","encrypt","aes","hex"))]
                log.warning(f"[AUTODISCOVERY] authKey/bindingKey assenti. Chiavi candidate nel device: {candidate_keys or list(selected_device.keys())}")
                lan_key_hex = _try_fetch_lan_key_from_cloud(
                    base_url=base_url,
                    token=token,
                    headers=headers,
                    device_key=device_key,
                    product_key=product_key,
                )
                if lan_key_hex:
                    log.info("[AUTODISCOVERY] LAN key discovered from cloud detail endpoint")
                else:
                    log.warning("[AUTODISCOVERY] LAN key non trovata via API (authKey/bindingKey assenti)")

    # ── Salva e applica ───────────────────────────────────────────────────
    controls = _try_fetch_tsl_controls(base_url, token, headers, product_key, device_key)

    discovered = {
        "wf_domain":    domain,
        "base_url":     base_url,
        "accel_url":    os.getenv("ACCEL_URL", ""),
        "device_key":   device_key,
        "product_key":  product_key,
        "accel_client": accel_cli,
        "lan_key_hex":  lan_key_hex,
        "token":        token,
    }
    socket_devices = _extract_socket_devices(devices)
    if socket_devices:
        discovered["smart_socket_devices"] = socket_devices
        log.info(f"[AUTODISCOVERY] Smart socket trovate: {len(socket_devices)}")
    if controls:
        discovered["controls"] = controls
    _save_cache(discovered, platform)
    _apply_discovered(discovered)
    log.info("[AUTODISCOVERY] Discovery completata.")
