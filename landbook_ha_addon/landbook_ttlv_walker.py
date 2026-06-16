"""Generic TTLV walker driven by the TSL schema dumped to /data/landbook_tsl.json.

The Landbook FPPT-T2400 firmware reports telemetry inside the encrypted bus payload
using the same TTLV encoding it accepts for commands:

    tag  (2 bytes big-endian) = (id << 3) | type
    type 0  → BOOL false (no value)
    type 1  → BOOL true  (no value)
    type 2  → INT  : [prefix 1B = len-1][value len bytes big-endian]
    type 4  → STRUCT: [count 2B][sub-field][sub-field]...

The current decode_bus_payload reverse-engineers this with hand-tuned offsets and
range checks. This walker uses the TSL schema (id→code, type, specs.step) so the
range checks and per-field hex addresses are no longer needed.

It is intentionally side-effect free and returns a dict {code: value}; the bridge
chooses where to publish it (shadow MQTT topic or main one).
"""

import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("ttlv_walker")

TSL_DUMP_PATH = "/data/landbook_tsl.json"

TYPE_BOOL_FALSE = 0
TYPE_BOOL_TRUE  = 1
TYPE_INT        = 2
TYPE_STRUCT     = 4


# ── Schema loader ───────────────────────────────────────────────────────────

_schema_cache: Optional[dict] = None


def _is_debug() -> bool:
    return os.environ.get("LANDBOOK_LOG_LEVEL", "info").lower() == "debug"


def load_tsl_schema(path: str = TSL_DUMP_PATH) -> dict:
    """Load the TSL dump produced by wf_autodiscovery._dump_tsl_to_data.

    Returns {} if missing — caller should fall back to the legacy decoder.
    The result is cached: a `force=True` reload is not exposed because the dump
    only changes after an explicit cloud refresh, which restarts the addon."""
    global _schema_cache
    if _schema_cache is not None:
        return _schema_cache
    try:
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, ValueError) as e:
        log.debug(f"TSL dump not available ({e}); walker disabled")
        _schema_cache = {}
        return _schema_cache
    props = bundle.get("properties") or {}
    if not isinstance(props, dict):
        _schema_cache = {}
        return _schema_cache
    # Build id→entry index (top level only — struct sub-fields are looked up
    # under their parent's children map at decode time).
    id_index: Dict[int, dict] = {}
    for entry in props.values():
        ident = entry.get("id")
        if isinstance(ident, int):
            id_index[ident] = entry
    _schema_cache = {
        "properties": props,
        "id_index":   id_index,
        "product_key": bundle.get("product_key", ""),
        "fetched_at":  bundle.get("fetched_at", 0),
    }
    log.debug(f"TSL schema loaded: {len(props)} properties indexed")
    if not _is_debug():
        return _schema_cache
    print(f"[ttlv_walker] TSL schema loaded: {len(props)} properties, "
          f"{len(id_index)} top-level ids", flush=True)
    for code in sorted(props.keys()):
        entry = props[code]
        children = entry.get("children") or {}
        print(f"[ttlv_walker]   {code:32s} id={entry.get('id'):>4} "
              f"type={entry.get('type') or '?':10s} children={len(children)}",
              flush=True)
        for ccode in sorted(children.keys()):
            c = children[ccode]
            print(f"[ttlv_walker]     └─ {ccode:28s} id={c.get('id'):>4} "
                  f"type={c.get('type') or '?'}", flush=True)
    return _schema_cache


# ── TTLV reader ─────────────────────────────────────────────────────────────

def _read_one(buf: bytes, pos: int, end: int) -> Optional[Tuple[int, int, Any, int]]:
    """Parse one TTLV element starting at `pos`.

    Returns (id, type, value, new_pos) or None when the buffer can't satisfy
    the declared type — the caller decides whether to skip a byte and retry."""
    if pos + 2 > end:
        return None
    tag = int.from_bytes(buf[pos:pos + 2], "big")
    pos += 2
    ident = tag >> 3
    typ = tag & 7
    if typ == TYPE_BOOL_FALSE:
        return ident, typ, False, pos
    if typ == TYPE_BOOL_TRUE:
        return ident, typ, True, pos
    if typ == TYPE_INT:
        if pos >= end:
            return None
        prefix = buf[pos]
        pos += 1
        vlen = prefix + 1
        if vlen > 8 or pos + vlen > end:
            return None
        val = int.from_bytes(buf[pos:pos + vlen], "big")
        return ident, typ, val, pos + vlen
    if typ == TYPE_STRUCT:
        if pos + 2 > end:
            return None
        count = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2
        # Defensive cap: real structs in the FPPT-T2400 telemetry stay under ~32.
        if count > 64:
            return None
        children: list = []
        for _ in range(count):
            sub = _read_one(buf, pos, end)
            if sub is None:
                return None
            children.append(sub)
            pos = sub[3]
        return ident, typ, children, pos
    return None


# ── Scale + decode ──────────────────────────────────────────────────────────

def _scale_factor(entry: dict) -> float:
    """Extract a numeric scale from the TSL specs (step/scale/ratio).

    Aliyun's `specs.step` of 0.1 means the raw integer is in tenths. We support
    a few common keys because vendors sprinkle the scale around inconsistently."""
    specs = entry.get("specs")
    if isinstance(specs, dict):
        for key in ("step", "scale", "ratio", "precision"):
            v = specs.get(key)
            if v is None:
                continue
            try:
                f = float(v)
                if f > 0:
                    return f
            except (TypeError, ValueError):
                pass
    return 1.0


def _apply_scale(raw: Any, entry: dict) -> Any:
    if not isinstance(raw, (int, float)):
        return raw
    factor = _scale_factor(entry)
    if factor == 1.0:
        return raw
    scaled = raw * factor
    # Preserve int-ness when the scaling is integer-clean (e.g. step=1.0).
    if isinstance(raw, int) and factor.is_integer():
        return int(scaled)
    # Avoid floating-point drift for typical 0.1/0.01 steps.
    return round(scaled, 4)


def _decode_struct(children: list, struct_entry: dict, out: dict) -> None:
    """Map struct sub-fields by id using the parent's children schema."""
    child_schema = struct_entry.get("children") or {}
    child_index = {c.get("id"): c for c in child_schema.values() if isinstance(c.get("id"), int)}
    for cident, ctyp, cval, _ in children:
        cprop = child_index.get(cident)
        if not cprop:
            continue
        if ctyp == TYPE_STRUCT and isinstance(cval, list):
            _decode_struct(cval, cprop, out)
            continue
        out[cprop["code"]] = _apply_scale(cval, cprop)


def decode_payload(payload: bytes, schema: Optional[dict] = None) -> Dict[str, Any]:
    """Top-level entry point: walk the payload and return {tsl_code: value}.

    Unknown ids are silently skipped (the firmware emits service tags the TSL
    does not describe — e.g. session control). On malformed bytes we advance
    one byte and retry, which is forgiving of the leading frame markers the
    legacy decoder also handles heuristically."""
    if not payload:
        return {}
    if schema is None:
        schema = load_tsl_schema()
    id_index = schema.get("id_index") if isinstance(schema, dict) else None
    if not id_index:
        return {}
    out: Dict[str, Any] = {}
    pos, end = 0, len(payload)
    while pos < end:
        item = _read_one(payload, pos, end)
        if item is None:
            pos += 1
            continue
        ident, typ, val, new_pos = item
        entry = id_index.get(ident)
        if entry is None:
            pos = new_pos
            continue
        if typ == TYPE_STRUCT and isinstance(val, list):
            _decode_struct(val, entry, out)
        else:
            out[entry["code"]] = _apply_scale(val, entry)
        pos = new_pos
    return out
