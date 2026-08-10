"""landbook.cache_store — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    DEVICE_KEY,
    DISCOVERY_CACHE_PATH,
    _dprint,
)


def _device_key(args):
    return str(getattr(args, "device_key", "") or DEVICE_KEY).strip()


def _load_discovered_cache() -> dict:
    try:
        with open(DISCOVERY_CACHE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_discovered_cache(data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(DISCOVERY_CACHE_PATH), exist_ok=True)
        with open(DISCOVERY_CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception as exc:
        print(f"discovered cache write failed: {exc}", flush=True)



SWITCH_CACHE_PATH = "/data/landbook_switch_cache.json"
LAN_SENSOR_CACHE_MAX_AGE = 15 * 60
LAN_SENSOR_CACHE_KEYS = {
    "battery_percentage",
    "battery_remaining_wh",
    "remaining_time_minutes",
    "battery_temp",
    "battery_voltage",
    "battery_total_power",
    "battery_current",
}


def cleanup_disabled_cache_files(args):
    for path in (SWITCH_CACHE_PATH,):
        if not path:
            continue
        try:
            if os.path.exists(path):
                os.remove(path)
                _dprint(f"removed disabled cache file: {path}", flush=True)
        except Exception as exc:
            _dprint(f"cache file cleanup failed ({path}): {exc}", flush=True)


def load_lan_sensor_cache(path: str, max_age: int = LAN_SENSOR_CACHE_MAX_AGE) -> dict:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {}
    if not isinstance(data, dict) or data.get("source") != "lan":
        return {}
    try:
        updated_at = int(data.get("updated_at") or 0)
    except (TypeError, ValueError):
        return {}
    if updated_at <= 0 or time.time() - updated_at > max_age:
        return {}
    values = data.get("values")
    if not isinstance(values, dict):
        return {}
    return {key: values[key] for key in LAN_SENSOR_CACHE_KEYS if key in values}


def save_lan_sensor_cache(path: str, cache: dict, keys=None) -> None:
    if not path:
        return
    touched = set(keys or ())
    if touched and not (touched & LAN_SENSOR_CACHE_KEYS):
        return
    values = {key: cache[key] for key in LAN_SENSOR_CACHE_KEYS if key in cache}
    if not values:
        return
    payload = {
        "source": "lan",
        "updated_at": int(time.time()),
        "values": values,
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception as exc:
        _dprint(f"LAN sensor cache write failed: {exc}", flush=True)

