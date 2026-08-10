"""landbook.tsl_busmask — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
import argparse
import base64
import errno
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request

from landbook_lan_probe import encode_cmd, extract_frames, recv_some
from landbook_local_client import aes_decrypt, aes_encrypt, connect_and_login, ttlv_number

from landbook.constants import (
    _is_debug,
)


_BUS_MASK_CACHE = None
_BUS_MASK_SOURCE = ""
# 7=device_type, 18=measure_data (storici). Aggiunti (0.9.x, analisi log 10k righe):
# id che il firmware NON riporta MAI via LAN — chiederli nella mask è inutile e
# sospettato concausa dei freeze FC41D in standby (frame keepalive vuoti pv_data:0):
#   8=timed_grid_connection, 9=timed_charge_connection,
#   16=solar_panel_power_generation, 17=load_power_consumption,
#   27=mode, 30=mac_set, 38=screen_sleeptime_set,
#   47=quec_x_clear_data (comando clear-data: MAI da pollare).
# NB: 39=beep_setting_set risponde → resta incluso.
_BUS_MASK_EXCLUDED_IDS = {7, 8, 9, 16, 17, 18, 27, 30, 38, 47}
_BUS_MASK_EXCLUDED_CODES = {"device_type", "measure_data"}


def _read_tsl_bundle_for_bus_mask():
    """Read the current model TSL cache written at bootstrap."""
    for path in ("/data/landbook_tsl.json", "/share/landbook_tsl.json", "/data/discovered.json"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _iter_tsl_items(container):
    if isinstance(container, dict):
        for code, info in container.items():
            if isinstance(info, dict):
                yield str(code), info
    elif isinstance(container, list):
        for item in container:
            if isinstance(item, dict):
                code = item.get("code") or item.get("identifier") or item.get("identifierName") or item.get("name")
                yield str(code or ""), item


def _top_level_tsl_id(info):
    if not isinstance(info, dict):
        return None
    ident = info.get("id", info.get("abId", info.get("abid")))
    if ident is None:
        for key in ("resourceId", "attributeId", "attrId", "paramId"):
            ident = info.get(key)
            if ident is not None:
                break
    try:
        ident = int(ident)
    except Exception:
        return None
    if 0 < ident <= 0xFFFF:
        return ident
    return None


def _dedupe_ids(ids):
    deduped = []
    seen = set()
    for ident in ids:
        try:
            ident = int(ident)
        except Exception:
            continue
        if ident <= 0 or ident > 0xFFFF or ident in seen:
            continue
        seen.add(ident)
        deduped.append(ident)
    return sorted(deduped)


def _ids_from_full_tsl(bundle):
    ids = []
    for section in ("properties", "controls", "tsl_controls"):
        for code, info in _iter_tsl_items(bundle.get(section)):
            if not code or not isinstance(info, dict):
                continue
            kind = str(info.get("kind") or info.get("accessMode") or info.get("rwFlag") or "").lower()
            t = str(info.get("type") or info.get("dataType") or info.get("valueType") or "").upper()
            if t in ("EVENT", "FUNCTION") and "property" not in kind:
                continue
            # bus_mask uses top-level property/resource IDs only. Struct children
            # reuse small field IDs that collide with top-level IDs; including
            # them can request unrelated properties.
            ident = _top_level_tsl_id(info)
            if ident in _BUS_MASK_EXCLUDED_IDS or code in _BUS_MASK_EXCLUDED_CODES:
                continue
            if ident is not None:
                ids.append(ident)
    return _dedupe_ids(ids)


def _bus_mask_ids_from_tsl():
    global _BUS_MASK_SOURCE
    bundle = _read_tsl_bundle_for_bus_mask()
    ids = _ids_from_full_tsl(bundle)
    source = "full-tsl-business"
    _BUS_MASK_SOURCE = source if ids else ""
    if ids and _is_debug():
        print(f"[BUS-MASK] source={source} ids={ids}", flush=True)
    return ids


def resolve_bus_mask_ids(args=None):
    """Return top-level IDs from the cached product TSL."""
    global _BUS_MASK_CACHE
    if _BUS_MASK_CACHE is None:
        ids = _bus_mask_ids_from_tsl()
        if not ids:
            raise RuntimeError("TSL bus mask unavailable: /data/landbook_tsl.json missing or empty")
        _BUS_MASK_CACHE = ids
        src = f" source={_BUS_MASK_SOURCE}" if _BUS_MASK_SOURCE else ""
        print(f"[BUS-MASK] TSL business: {len(ids)} ids{src}", flush=True)
    return list(_BUS_MASK_CACHE)


# ── Switch / mode tables ─────────────────────────────────────────────────────


def invalidate_bus_mask_cache():
    global _BUS_MASK_CACHE, _BUS_MASK_SOURCE
    _BUS_MASK_CACHE = None
    _BUS_MASK_SOURCE = ""
