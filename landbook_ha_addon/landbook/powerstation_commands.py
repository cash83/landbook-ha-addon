"""landbook.powerstation_commands — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    BUS_REFRESH_TAG,
    DISCOVERY_CACHE_PATH,
    INTELLIGENT_CHARGING_WATTS,
    TIMED_CHARGE_CONNECTION_TAG,
    _boolish,
    _dprint,
    _is_debug,
)

from landbook.tsl_busmask import (
    resolve_bus_mask_ids,
)


def _intelligent_charge_index_from_watts(value) -> int:
    try:
        watts = int(round(float(value)))
    except (TypeError, ValueError):
        raise ValueError("invalid intelligent charging power")
    nearest = min(INTELLIGENT_CHARGING_WATTS, key=lambda x: abs(x - watts))
    return INTELLIGENT_CHARGING_WATTS.index(nearest)


def _intelligent_charge_watts_from_index(value) -> int:
    try:
        idx = int(value)
    except (TypeError, ValueError):
        idx = 0
    if idx < 0 or idx >= len(INTELLIGENT_CHARGING_WATTS):
        idx = 0
    return INTELLIGENT_CHARGING_WATTS[idx]


def _build_intelligent_charging_payload(watts) -> bytes:
    power_idx = _intelligent_charge_index_from_watts(watts)
    disabled = b"".join(ttlv_number(i, 0) for i in (1, 2, 3, 4))
    always_on = (
        ttlv_number(1, 127) +     # all weekdays
        ttlv_number(2, 1) +       # 00:01
        ttlv_number(3, 1439) +    # 23:59
        ttlv_number(4, power_idx)
    )
    # The firmware reports ARRAY-of-STRUCT as a STRUCT tag whose children are
    # anonymous id=0 STRUCT entries. Reuse that exact compact layout.
    entry_tag = (0 << 3) | 4
    entries = (
        entry_tag.to_bytes(2, "big") + (4).to_bytes(2, "big") + disabled +
        entry_tag.to_bytes(2, "big") + (4).to_bytes(2, "big") + always_on
    )
    return TIMED_CHARGE_CONNECTION_TAG.to_bytes(2, "big") + (2).to_bytes(2, "big") + entries


def _extract_intelligent_charging_power(payload: bytes):
    pos = payload.find(TIMED_CHARGE_CONNECTION_TAG.to_bytes(2, "big"))
    if pos < 0 or pos + 4 > len(payload):
        return None
    pos += 2
    count = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    if count <= 0 or count > 8:
        return None
    best_power = None
    for _ in range(count):
        if pos + 4 > len(payload):
            return best_power
        tag = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        if tag != 0x0004:
            return best_power
        field_count = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        fields = {}
        for _field in range(field_count):
            if pos + 3 > len(payload):
                return best_power
            ftag = int.from_bytes(payload[pos:pos + 2], "big")
            pos += 2
            fid = ftag >> 3
            ftyp = ftag & 7
            if ftyp in (0, 1):
                fields[fid] = 1 if ftyp == 1 else 0
                continue
            if ftyp != 2:
                return best_power
            prefix = payload[pos]
            pos += 1
            marker = prefix & 0x7F
            vlen = 2 if marker == 0x09 else marker + 1
            if vlen > 8 or pos + vlen > len(payload):
                return best_power
            val = int.from_bytes(payload[pos:pos + vlen], "big")
            pos += vlen
            if prefix & 0x80:
                val = -val
            fields[fid] = val
        if int(fields.get(1) or 0) or int(fields.get(2) or 0) or int(fields.get(3) or 0):
            best_power = _intelligent_charge_watts_from_index(fields.get(4, 0))
    return best_power



def _next_packet_id(args):
    pid = int(getattr(args, "_lan_packet_id", 1) or 1) & 0xFFFF
    if pid == 0:
        pid = 1
    args._lan_packet_id = 1 if pid >= 0xFFFE else pid + 1
    return pid


def _send_frame(sock, args, frame):
    min_interval = max(0.0, float(getattr(args, "device_tx_min_interval", 0.6) or 0.6))
    last_tx = float(getattr(args, "_last_device_tx", 0.0) or 0.0)
    wait = last_tx + min_interval - time.time()
    if wait > 0:
        time.sleep(wait)
    sock.sendall(frame)
    args._last_device_tx = time.time()


_TSL_CONTROLS_CACHE = None



def _load_tsl_controls():
    global _TSL_CONTROLS_CACHE
    if _TSL_CONTROLS_CACHE is not None:
        return _TSL_CONTROLS_CACHE
    controls = {}
    try:
        with open(DISCOVERY_CACHE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for raw_controls in (data.get("properties"), data.get("controls"), data.get("tsl_controls")):
            if isinstance(raw_controls, list):
                raw_controls = {
                    str(item.get("code") or item.get("identifier") or item.get("identifierName")): item
                    for item in raw_controls
                    if isinstance(item, dict)
                }
            if isinstance(raw_controls, dict):
                controls.update({str(k): v for k, v in raw_controls.items() if isinstance(v, dict)})
    except Exception as exc:
        _dprint(f"TSL controls cache unavailable: {exc}", flush=True)
    _TSL_CONTROLS_CACHE = controls
    return controls


def _tsl_control_info(code, default_type=None):
    info = dict(_load_tsl_controls().get(code) or {})
    if default_type and "type" not in info:
        info["type"] = default_type
    control_id = info.get("id", info.get("abId", info.get("abid")))
    if control_id is None:
        raise ValueError(f"TSL control id not found for {code}")
    info["id"] = int(control_id)
    raw_type = str(info.get("type") or "").upper()
    data_type = str(info.get("dataType") or info.get("valueType") or "").upper()
    if raw_type in ("", "PROPERTY", "FUNCTION", "EVENT"):
        raw_type = ""
    info["type"] = data_type or raw_type or str(default_type or "ENUM").upper()
    return info


def _build_tsl_payload(control_info, value):
    control_id = int(control_info["id"])
    data_type = str(control_info.get("type") or control_info.get("dataType") or "ENUM").upper()
    if data_type == "BOOL":
        return ((control_id << 3) | (1 if _boolish(value) else 0)).to_bytes(2, "big")
    if data_type in ("ENUM", "INT", "INTEGER", "LONG", "UINT", "UINT16", "UINT32"):
        return ttlv_number(control_id, int(value))
    if data_type in ("FLOAT", "DOUBLE"):
        return ttlv_number(control_id, int(round(float(value))))
    return ttlv_number(control_id, int(value))



def _build_tsl_info_frame(info, value, key, iv, args, default_type=None):
    merged = dict(info or {})
    if default_type and "type" not in merged:
        merged["type"] = default_type
    payload = _build_tsl_payload(merged, value)
    if _is_debug() or getattr(args, "debug_tsl_commands", False):
        print(
            "TSL command "
            f"code={merged.get('code')} id={merged.get('id')} "
            f"type={merged.get('type') or merged.get('dataType') or default_type} "
            f"value={value} payload={payload.hex(' ')}",
            flush=True,
        )
    return encode_cmd(0x0013, _next_packet_id(args), aes_encrypt(payload, key, iv))


def send_bus_refresh(sock, key, iv, args, mode=3):
    payload = BUS_REFRESH_TAG.to_bytes(2, "big") + int(mode).to_bytes(2, "big")
    frame = encode_cmd(0x0013, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"sent bus_refresh mode={mode}", flush=True)


def send_bus_mask(sock, key, iv, args, ids=None):
    mask_ids = ids if ids is not None else resolve_bus_mask_ids(args)
    payload = b"".join(int(x).to_bytes(2, "big") for x in mask_ids)
    frame = encode_cmd(0x0011, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"sent bus_mask ids={len(mask_ids)} mode=tsl", flush=True)


def send_report_subscription(sock, key, iv, args):
    interval = int(getattr(args, "report_interval", 10) or 10)
    payload = ttlv_number(1, interval) + ttlv_number(2, 1)
    frame = encode_cmd(28729, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"LAN report subscription sent (interval={interval}s)", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# Battery cache
# ══════════════════════════════════════════════════════════════════════════════



def invalidate_tsl_controls_cache():
    global _TSL_CONTROLS_CACHE
    _TSL_CONTROLS_CACHE = None
