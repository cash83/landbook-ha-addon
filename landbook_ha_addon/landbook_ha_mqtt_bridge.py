"""
Landbook/Wonderfree generic TSL-driven LAN to Home Assistant MQTT bridge.

Design: cloud provisioning caches LAN key and TSL; runtime connects over LAN,
subscribes once, sends a top-level TSL bus_mask plus bus_refresh every 10s,
decodes frames, and reconnects on silence or network errors.
"""

import argparse
import base64
import errno
import json
import os
import socket
import sys
import time
import urllib.parse
import urllib.request

from landbook_lan_probe import encode_cmd, extract_frames, recv_some
from landbook_local_client import aes_decrypt, aes_encrypt, connect_and_login, ttlv_number


def _is_debug():
    return os.environ.get("LANDBOOK_LOG_LEVEL", "info").lower() == "debug"

def _dprint(*args, **kwargs):
    if _is_debug():
        import builtins
        builtins.print(*args, **kwargs)


# ── Timing ───────────────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL     = 10    # LAN keepalive (seconds)
MQTT_PING_INTERVAL     = 30    # MQTT keepalive
FRAME_SILENCE_TIMEOUT  = 30    # tollera il ciclo bus_mask
SENSOR_RECONNECT_AFTER      = 50  # dopo ~50s senza sensori: evento/riconnessione per automazioni HA
                                   # (alzato da 30s: il device cicla naturalmente Low/LAN+WiFi reporting
                                   # ogni ~28-30s, e una soglia troppo vicina scambiava quel ciclo normale
                                   # per un freeze, causando reconnect inutili)
BUS_REFRESH_MIN_GAP    = 5     # debounce: non rimandare bus_mask/bus_refresh se già inviati da meno di Ns
SENSOR_SILENCE_RESTART = 180  # dopo 3 min senza sensori: riavvio processo
REPORT_RESUBSCRIBE     = 120   # subscription rara
BUS_MASK_INTERVAL      = 10    # simple LAN: bus_mask + bus_refresh fissi ogni ~10s
RECONNECT_DELAY_INIT   = 2.0   # recovery LAN rapido dopo freeze/unreachable
RECONNECT_DELAY_MAX    = 5.0   # non aspettare 17/25/30s tra retry
UNREACHABLE_RESTART    = 180   # restart process after 3 min unreachable
UNREACHABLE_WIFI_FROZEN_ALERT = 30  # dopo ~30s LAN irraggiungibile: alert wifi_frozen
UNREACHABLE_STOP_AFTER = 2          # dopo 2 alert LAN irraggiungibile consecutivi: ferma l'add-on (vincolato comunque a MIN_SECONDS_BEFORE_STOP)
BROKEN_PIPE_RESTART    = 30    # restart process after 30s broken-pipe loop
AVAILABILITY_HOLD      = 300   # hold MQTT "online" for 5 min during outage
COMMAND_DUPLICATE_WINDOW = 0.8 # drop same command repeated by HA/UI immediately
COMMAND_OPPOSITE_WINDOW  = 2.5 # drop fast ON/OFF or select A/B bounces
GRID_OPPOSITE_WINDOW     = 3.0 # grid/micro-inverter is the most fragile command
# ── WiFi freeze detection ─────────────────────────────────────────────────────
# Il modulo WiFi della powerstation può congelare il task di reporting mantenendo
# il TCP vivo (gli switch continuano a funzionare ma i sensori non arrivano).
# Dopo WIFI_FROZEN_ALERT_AFTER: pubblica evento MQTT per automazioni HA.
WIFI_FROZEN_ALERT_AFTER  = 1     # evento MQTT al primo freeze rilevato
WIFI_FROZEN_ALERT_COOLDOWN = 50  # consenti un nuovo alert dopo ~50s se il freeze persiste
WIFI_FROZEN_STOP_AFTER = 2          # dopo 2 freeze consecutivi: ferma l'add-on (vincolato comunque a MIN_SECONDS_BEFORE_STOP)
MQTT_RECONNECT_COOLDOWN = 20   # tra un reconnect MQTT e il successivo, se il precedente è fallito
# L'automazione HA che riavvia il WiFi del router, attivata dal primo alert
# wifi_frozen, spegne il WiFi e lo riaccende dopo ~20s. L'addon non deve
# spegnersi PRIMA che quel ciclo sia completato, altrimenti muore proprio
# mentre la rete sta per tornare e non c'è più nessuno a riconnettersi.
MIN_SECONDS_BEFORE_STOP = 35   # margine sopra i 20s del router prima di fermare l'add-on

# ── Device identity ──────────────────────────────────────────────────────────
DEVICE_KEY   = "000000000000"
DEVICE_NAME  = "Landbook LAN Device"
def _read_app_version() -> str:
    """Single source of truth: config.yaml. Avoids the trap where bumping the
    addon required editing three identical strings (config.yaml, addon_run.py,
    bridge) and the bridge banner ended up stale (0.3.84 long after 0.3.91)."""
    for path in ("/app/config.yaml", "/data/config.yaml",
                 os.path.join(os.path.dirname(__file__), "config.yaml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("version:"):
                        return line.split(":", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    return "unknown"

APP_VERSION  = _read_app_version()
DISCOVERY_CACHE_PATH = "/data/discovered.json"
PLATFORMS_PATH = "/app/platforms.json"
SMART_SOCKET_PRODUCT_KEYS = {"p11spk"}
SMART_SOCKET_SENSOR_DEFS = {
    "power": ("Power", "W", "power", "measurement"),
    "voltage": ("Voltage", "V", "voltage", "measurement"),
    "current": ("Current", "A", "current", "measurement"),
    "apparent_power": ("Apparent Power", "VA", "apparent_power", "measurement"),
    "power_factor": ("Power Factor", None, "power_factor", "measurement"),
    "energy": ("Energy", "kWh", "energy", "total_increasing"),
}
SMART_SOCKET_ON_HEX = "aa aa 00 07 21 00 05 00 13 00 09"
SMART_SOCKET_OFF_HEX = "aa aa 00 07 21 00 05 00 13 00 08"
# Poll consecutivi in cui una presa è assente dalla device-list cloud prima di
# rimuoverla da Home Assistant (eliminata dall'app).
SMART_SOCKET_NOT_FOUND_LIMIT = 3
SMART_SOCKET_FALLBACK_DEVICES = (
    {
        "device_key": "00D6CBEDD001",
        "product_key": "p11sPk",
        "name": "SPP 16A2_D001",
        "product_name": "Smart socket",
    },
    {
        "device_key": "00D6CBEDCFA7",
        "product_key": "p11sPk",
        "name": "Presa Ha",
        "product_name": "Smart socket",
    },
)
INTELLIGENT_CHARGING_POWER_ID = "intelligent_charging_power"
INTELLIGENT_CHARGING_WATTS = (200, 400, 600, 800)
TIMED_CHARGE_CONNECTION_TAG = 0x004C  # id 9, compact STRUCT/ARRAY encoding
OUTPUT_POWER_TAG = 0x00EA
BUS_REFRESH_TAG  = 0x009A
# Runtime bus_mask is generated only from the discovered TSL.
# Legacy fallback was removed because on this powerstation it caused an endless
# TSL→legacy loop with only pv_data:0 frames.
_BUS_MASK_CACHE = None
_BUS_MASK_SOURCE = ""
_BUS_MASK_EXCLUDED_IDS = {7, 18}
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
SWITCH_HEX = {}  # populated from TSL BOOL controls at startup

# Codes the firmware reports inconsistently between the full "work_profile"
# frame and shorter battery-only frames in the same polling cycle (observed:
# led_status_set reads True in the work_profile frame right after a command,
# False in the battery-only frame a moment later). For these, only trust the
# value when it comes from a work_profile frame — otherwise the walker-driven
# switch/select publish below is skipped for that code on that frame.
FRAME_COHERENCE_REQUIRES_WORK_PROFILE = {"led_status_set"}

MODE_LABEL_BY_VAL = {}

AC_STATE_WORDS   = {0x0070: "OFF", 0x0071: "ON"}
DC_STATE_WORDS   = {0x0078: "OFF", 0x0079: "ON"}
GRID_STATE_WORDS = {0x00E0: "OFF", 0x00E1: "ON"}

DEVICE_STATUS_LABELS = {
    0: "Standby",               # niente attivo
    1: "In carica",             # batteria in carica (da PV o AC)  — TSL: "Charge"
    2: "In scarica",            # batteria si scarica verso i carichi — TSL: "Discharge"
    3: "Carica e scarica",      # PV carica batteria + output attivo — TSL: "Charge and Discharge"
    4: "Bypass",                # ingresso AC direttamente in uscita — TSL: "Bypass Mode"
}

# Il profilo HMI/work_profile contiene campi interni che possono sembrare
# codici errore ma non sempre lo sono: osservato field[3]=40 mentre l'app
# ufficiale mostrava solo "Carica scarica" e nessun fault. Per HA pubblichiamo
# come fault solo codici noti/riconosciuti; altri valori restano raw se non mappati.
OFFICIAL_FAULT_CODES = {
    0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14,
    101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    138, 139, 143, 144, 145,
    180, 181, 182, 183,
    190, 191, 192, 193, 199,
    200, 201, 202, 203, 204, 205, 207,
}
FAULT_CODE_LABELS = {
    0:   "Normale",
    1:   "Errore E01", 2:   "Errore E02", 3:   "Errore E03", 4:   "Errore E04",
    7:   "Errore E07", 8:   "Errore E08", 9:   "Errore E09",
    10:  "Errore E010", 11:  "Errore E011", 12:  "Errore E012",
    13:  "Errore E013", 14:  "Errore E014",
    101: "Errore E101", 102: "Errore E102", 103: "Errore E103",
    104: "Errore E104", 105: "Errore E105", 106: "Errore E106",
    107: "Errore E107", 108: "Errore E108", 109: "Errore E109",
    110: "Errore E110", 138: "Errore E138", 139: "Errore E139",
    143: "Errore E143", 144: "Errore E144", 145: "Errore E145",
    180: "Errore E180", 181: "Errore E181", 182: "Errore E182",
    183: "Errore E183", 190: "Errore E190", 191: "Errore E191",
    192: "Errore E192", 193: "Errore E193", 199: "Errore E199",
    200: "Errore E200", 201: "Errore E201", 202: "Errore E202",
    203: "Errore E203", 204: "Errore E204", 205: "Errore E205",
    207: "Errore E207",
}

STATE_TAGS = {
    "beep":          {0x0138: "OFF", 0x0139: "ON"},
    "slow_reporting":{0x0108: "OFF", 0x0109: "ON"},
}
VALUE_STATES = {
    "led":   {0x0102: {0: "OFF", 1: "ON"}},
    "screen":{0x0132: {0: "ON", 10: "OFF"}},
}
LEGACY_COMMAND_STATE_CLEANUP = {"led", "screen", "high_frequency_reporting", "smart_socket_mode"}

SWITCH_DISCOVERY_META = {}


def _first_existing_switch_id(*candidates):
    for command_id in candidates:
        if command_id in SWITCH_HEX:
            return command_id
    return None


def _grid_command_id():
    return _first_existing_switch_id("grid_power_switch_set", "grid")


def _dc_command_id():
    return _first_existing_switch_id("dc_switch", "dc")


def _ac_command_id():
    return _first_existing_switch_id("ac_switch", "ac")


def _canonical_command_id(command_id):
    if command_id == "grid":
        return _grid_command_id() or command_id
    if command_id == "dc":
        return _dc_command_id() or command_id
    if command_id == "ac":
        return _ac_command_id() or command_id
    return command_id


# ── Sensor definitions ───────────────────────────────────────────────────────
SENSOR_DEFS = {}  # populated from TSL readable properties at startup

# ── TSL-driven overlay ───────────────────────────────────────────────────────
# The cloud TSL defines the readable/writable codes for the current model.
# The LAN decoder then publishes only values actually observed from the device,
# so new model-specific telemetry can appear without hard-coded entities.
try:
    from landbook_tsl_discovery import (
        build_switch_hex_overlay as _build_switch_hex_overlay,
        build_sensor_defs_overlay as _build_sensor_defs_overlay,
        build_switch_meta_overlay as _build_switch_meta_overlay,
    )
    _tsl_switch_overlay = _build_switch_hex_overlay(existing=SWITCH_HEX)
    _tsl_sensor_overlay = _build_sensor_defs_overlay(existing=SENSOR_DEFS)
    _tsl_switch_meta    = _build_switch_meta_overlay()
    for k, v in _tsl_switch_overlay.items():
        SWITCH_HEX[k] = v
    for k, v in _tsl_sensor_overlay.items():
        SENSOR_DEFS[k] = v
    _removed_static_switches = []
    for _sid in list(SWITCH_HEX):
        if "id" not in SWITCH_HEX[_sid]:
            _removed_static_switches.append(_sid)
            del SWITCH_HEX[_sid]
    # Keep curated baseline switches even when a richer TSL select exists on the
    # same code. Example: LED can be exposed both as a quick ON/OFF switch and
    # as a full brightness/effect select.
    _shadowed_baseline = _removed_static_switches
    if _is_debug():
        print(f"[tsl_discovery] overlay applied: +{len(_tsl_switch_overlay)} switches "
              f"({sorted(_tsl_switch_overlay.keys())}), +{len(_tsl_sensor_overlay)} sensors "
              f"({sorted(_tsl_sensor_overlay.keys())}), "
              f"baseline switches kept with selects: {sorted(SWITCH_HEX.keys())}", flush=True)
    else:
        print(f"[tsl_discovery] overlay applied: +{len(_tsl_switch_overlay)} switches, "
              f"+{len(_tsl_sensor_overlay)} sensors", flush=True)
    _BASELINE_SHADOWED_BY_SELECT = _shadowed_baseline
except Exception as _exc:
    print(f"[tsl_discovery] overlay skipped: {_exc}", flush=True)
    _tsl_switch_meta = {}
    _BASELINE_SHADOWED_BY_SELECT = []
    SWITCH_HEX.clear()

FIRMWARE_SENSOR_IDS = {"firmware_version_set", "firmware_version_bms", "firmware_version_mppt", "firmware_version_inv"}
BMS_CELL_SENSOR_IDS = {f"battery_cell_{c:02d}_voltage" for c in range(1, 14)}
BMS_INFO_SENSOR_IDS = BMS_CELL_SENSOR_IDS | {"battery_cycles", "bms_allow_max_charge_current", "bms_mos_status"}
BATTERY_INFO_SENSOR_IDS = {"battery_percentage", "battery_voltage", "battery_temp", "battery_remaining_wh", "remaining_time_minutes"}
EXPIRING_SENSOR_IDS = BATTERY_INFO_SENSOR_IDS | BMS_INFO_SENSOR_IDS | {
    "battery_current", "battery_total_power",
    "device_status", "fault_code", "fault_code_raw",
    "pv_input_power", "pv_panel_voltage",
    "grid_voltage", "grid_freq", "grid_b_power",
    "ac_input_power", "ac_output_power", "dc_output_power",
    "usb_a1_voltage", "usb_a1_power", "usb_a1_current",
    "usb_a2_voltage", "usb_a2_power", "usb_a2_current",
    "usb_a3_voltage", "usb_a3_power", "usb_a3_current",
    "usb_a4_voltage", "usb_a4_power", "usb_a4_current",
    "typec_1_voltage", "typec_1_power", "typec_1_current",
    "typec_2_voltage", "typec_2_power", "typec_2_current",
    "dc12v_voltage", "dc12v_power", "dc12v_current",
    "dc24v_voltage", "dc24v_power", "dc24v_current",
    "total_input_power", "total_output_power",
}
SENSOR_DISPLAY_PRECISION = {
    **{s: 3 for s in BMS_CELL_SENSOR_IDS},
    "battery_voltage": 1, "battery_current": 2, "grid_voltage": 1,
    "usb_a1_voltage": 1, "usb_a1_current": 2, "usb_a2_voltage": 1, "usb_a2_current": 2,
    "usb_a3_voltage": 1, "usb_a3_current": 2, "usb_a4_voltage": 1, "usb_a4_current": 2,
    "typec_1_voltage": 1, "typec_1_current": 2, "typec_2_voltage": 1, "typec_2_current": 2,
    "dc12v_voltage": 1, "dc12v_current": 2, "dc24v_voltage": 1, "dc24v_current": 2,
}
DC_OUTPUT_SENSOR_KEYS = (
    "dc_output_power",
    "usb_a1_voltage", "usb_a1_power", "usb_a1_current",
    "usb_a2_voltage", "usb_a2_power", "usb_a2_current",
    "usb_a3_voltage", "usb_a3_power", "usb_a3_current",
    "usb_a4_voltage", "usb_a4_power", "usb_a4_current",
    "typec_1_voltage", "typec_1_power", "typec_1_current",
    "typec_2_voltage", "typec_2_power", "typec_2_current",
    "dc12v_voltage", "dc12v_power", "dc12v_current",
    "dc24v_voltage", "dc24v_power", "dc24v_current",
)
AC_TRANSIENT_ZERO_KEYS = ("grid_voltage", "grid_b_power", "ac_input_power", "ac_output_power")
NON_MEANINGFUL_SENSOR_KEYS = {
    "ac_data", "battery_data", "dc_data", "grid_data", "pv_data", "pack_data",
    "measure_data", "temp_data_no", "bms_celldata_no", "work_profile",
    "device_key", "device_type",
    "output_power_set", "smart_socket_mode", "power_retention_set",
    "high_frequency_reporting",
}


def _has_meaningful_sensor_data(decoded: dict, args=None) -> bool:
    if not decoded:
        return False
    for key in decoded:
        if key in NON_MEANINGFUL_SENSOR_KEYS:
            continue
        if key in SWITCH_HEX:
            continue
        if args is not None:
            if key in (getattr(args, "_tsl_select_catalog", {}) or {}):
                continue
            if key in (getattr(args, "_tsl_number_catalog", {}) or {}):
                continue
        try:
            if key in globals().get("_NON_SENSOR_EXACT", set()):
                continue
            info = _load_tsl_controls().get(key) or {}
            if info.get("writable"):
                continue
        except Exception:
            pass
        return True
    return False

# ── MQTT discovery: object_id identici all'integrazione custom ────────────────
DEVICE_OBJECT_ID = "landbook"

SWITCH_OBJECT_ID_OVERRIDES = {}
_DIAGNOSTIC_SENSOR_IDS = set()
_DIAGNOSTIC_PREFIXES = ()


def _entity_category(key: str):
    if key in _DIAGNOSTIC_SENSOR_IDS:
        return "diagnostic"
    if any(key.startswith(p) for p in _DIAGNOSTIC_PREFIXES):
        return "diagnostic"
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Decoder helpers  (protocol reverse-engineering — do not modify)
# ══════════════════════════════════════════════════════════════════════════════

def _u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "big", signed=False)


def _s16_prefixed(data: bytes, off: int):
    if off < 0 or off + 3 > len(data):
        return None
    prefix = data[off]
    value = int.from_bytes(data[off + 1:off + 3], "big", signed=False)
    return -value if prefix & 0x80 else value


def _between(value, low, high):
    return value is not None and low <= value <= high


def _tag_u16(blob: bytes, tag: bytes):
    i = blob.find(tag)
    return None if i < 0 else _u16(blob, i + 2)


def _tag_prefixed_s16(blob: bytes, tag: bytes):
    i = blob.find(tag)
    return None if i < 0 else _s16_prefixed(blob, i + 2)



def _tag_battery_power_after(blob: bytes, tag: bytes, after_tag: bytes):
    after = blob.find(after_tag)
    start = after + 4 if after >= 0 else 0
    i = blob.find(tag, start)
    if i < 0 or i + 5 > len(blob):
        return None
    raw = blob[i + 2:i + 5]
    if raw[2] == 0 and raw[0] in (0x00, 0x80):
        return -raw[1] if raw[0] & 0x80 else raw[1]
    return _s16_prefixed(blob, i + 2)


def _read_compact_ttlv_int(data: bytes, pos: int, end: int):
    """Read the compact integer encoding used inside Landbook telemetry structs."""
    if pos >= end:
        return None, pos
    prefix = data[pos]
    marker = prefix & 0x7F
    # Most fields use len-1. This firmware also emits 0x09 for 2-byte values
    # such as battery voltage (observed: 00 1A 09 02 07 -> 519 -> 51.9V).
    vlen = 2 if marker == 0x09 else marker + 1
    if vlen < 1 or vlen > 8 or pos + 1 + vlen > end:
        return None, pos
    value = int.from_bytes(data[pos + 1:pos + 1 + vlen], "big", signed=False)
    if prefix & 0x80:
        value = -value
    return value, pos + 1 + vlen


def _apply_battery_data_struct(payload: bytes, out: dict) -> bool:
    """Decode top-level battery_data (id=3, tag 0x001c) from real LAN frames."""
    search_from = 0
    while True:
        idx = payload.find(b"\x00\x1c", search_from)
        if idx < 0:
            return False
        search_from = idx + 1
        if idx + 4 > len(payload):
            continue
        count = _u16(payload, idx + 2)
        if count is None or count <= 0 or count > 16:
            continue
        pos = idx + 4
        values = {}
        ok = True
        for _ in range(count):
            if pos + 3 > len(payload):
                ok = False
                break
            tag = _u16(payload, pos)
            pos += 2
            typ = tag & 0x07
            ident = tag >> 3
            if typ != 0x02:
                ok = False
                break
            value, new_pos = _read_compact_ttlv_int(payload, pos, len(payload))
            if new_pos == pos:
                ok = False
                break
            values[ident] = value
            pos = new_pos
        if not ok or len(values) < 3:
            continue

        soc = values.get(1)
        remaining = values.get(2)
        voltage_raw = values.get(3)
        power = values.get(5)
        temp = values.get(6)

        changed = False
        if _between(soc, 0, 100):
            out["battery_percentage"] = int(soc)
            changed = True
        if _between(remaining, 0, 65534):
            out["remaining_time_minutes"] = int(remaining)
            changed = True
        voltage = None
        if _between(voltage_raw, 400, 700):
            voltage = round(float(voltage_raw) / 10.0, 1)
        elif _between(voltage_raw, 40, 70):
            voltage = float(voltage_raw)
        if voltage is not None:
            out["battery_voltage"] = voltage
            changed = True
        if _between(power, -3000, 3000):
            out["battery_total_power"] = int(power)
            if voltage is not None and abs(float(voltage)) > 0:
                out["battery_current"] = round(float(power) / float(voltage), 2)
            changed = True
        if _between(temp, -40, 120):
            out["battery_temp"] = int(temp)
            changed = True
        return changed



def _ascii(data: bytes):
    if not data or any(b < 32 or b > 126 for b in data):
        return None
    return data.decode("ascii", errors="replace")


def _extract_bus_strings(payload: bytes, out: dict) -> None:
    string_fields = {
        0x00F3: "device_key",
        0x0113: "firmware_version_set",
        0x011B: "firmware_version_bms",
        0x0123: "firmware_version_mppt",
        0x012B: "firmware_version_inv",
        0x0143: "work_profile",
    }
    i = 0
    while i + 4 <= len(payload):
        fid = _u16(payload, i)
        ln = _u16(payload, i + 2)
        if fid is not None and ln is not None and 0 < ln <= 64 and i + 4 + ln <= len(payload):
            name = string_fields.get(fid)
            val = _ascii(payload[i + 4:i + 4 + ln])
            if name and val is not None:
                out[name] = val
                i += 4 + ln
                continue
        i += 1


def _extract_output_power_set(payload: bytes, out: dict) -> None:
    i = payload.find(OUTPUT_POWER_TAG.to_bytes(2, "big"))
    if i < 0:
        return

    # Commands use tag + signed-prefix + u16 (00 EA 01 00 8C for 140W).
    # Status reports from the device can use tag + plain u16 (00 EA 00 8C).
    value = _s16_prefixed(payload, i + 2) if i + 5 <= len(payload) else None
    if not (_between(value, 100, 800) and value % 10 == 0):
        value = _u16(payload, i + 2) if i + 4 <= len(payload) else None

    if _between(value, 100, 800):
        out["output_power_set"] = int(value)


def _parse_work_profile(wp: str, out: dict) -> None:
    # hmi_data_no = "device_status, field1_unknown, field2_candidate_uptime, fault_code, ..."
    #
    # ATTENZIONE: field[1] era storicamente etichettato "uptime_minutes_lan", ma
    # i dati raccolti (storico HA + TSL cloud) mostrano che NON si comporta come
    # un uptime: lo stesso valore (es. 257) è tornato identico a distanza di
    # 20+ minuti, e in altre sessioni è rimasto fisso per ore mentre field[2]
    # cresceva di 1 ogni minuto. field[1] resta pubblicato per compatibilità/
    # diagnostica ma sotto un nome neutro. field[2] è il candidato più plausibile
    # per il vero uptime in minuti (cresce in modo monotono nei log osservati) —
    # va trattato come ipotesi da confermare, non come dato certo.
    try:
        fields = wp.split(",")
        if len(fields) < 2:
            return
        status = int(fields[0])
        field1_unknown = int(fields[1])
        if 0 <= status <= 15:
            out["device_status_raw"] = status
            out["device_status"] = DEVICE_STATUS_LABELS.get(status, f"Stato {status}")
        if 0 <= field1_unknown <= 100000:
            out["hmi_field1_raw"] = field1_unknown
            # Manteniamo anche il vecchio nome per non rompere automazioni/dashboard
            # esistenti che lo referenziano, ma è deprecato: non è un uptime affidabile.
            out["uptime_minutes_lan"] = field1_unknown
        if len(fields) > 2:
            try:
                field2 = int(fields[2])
                if 0 <= field2 <= 100000:
                    out["hmi_field2_uptime_candidate"] = field2
            except ValueError:
                pass
        # field[3] puo' contenere anche stati HMI interni: accettalo come fault
        # solo se e' un codice presente nel TSL ufficiale.
        if len(fields) > 3:
            try:
                fc = int(fields[3])
                if fc in OFFICIAL_FAULT_CODES:
                    out["fault_code_raw"] = fc
                    out["fault_code"] = FAULT_CODE_LABELS.get(fc, f"Errore E{fc}")
                else:
                    out["fault_code_raw"] = 0
                    out["fault_code"] = "Normale"
            except ValueError:
                pass
    except (ValueError, IndexError):
        pass


def _extract_dc_data(payload: bytes) -> dict:
    out: dict = {}
    marker = b"\x00\x34\x00\x11"
    idx = payload.find(marker)
    if idx < 0:
        return out
    section = payload[idx + len(marker):idx + len(marker) + 96]
    field_map = {
        1: ("dc_output_power", "power"),
        2: ("usb_a1_voltage", "voltage"), 3: ("usb_a1_power", "power"),
        4: ("usb_a2_voltage", "voltage"), 5: ("usb_a2_power", "power"),
        6: ("usb_a3_voltage", "voltage"), 7: ("usb_a3_power", "power"),
        8: ("usb_a4_voltage", "voltage"), 9: ("usb_a4_power", "power"),
        10: ("typec_1_voltage", "voltage"), 11: ("typec_1_power", "power"),
        12: ("typec_2_voltage", "voltage"), 13: ("typec_2_power", "power"),
        14: ("dc12v_voltage", "voltage"), 15: ("dc12v_power", "power"),
        16: ("dc24v_voltage", "voltage"), 17: ("dc24v_power", "power"),
    }
    i = 0
    while i + 4 <= len(section):
        tag = _u16(section, i)
        value = _u16(section, i + 2)
        if tag is None or value is None:
            break
        field_id = tag >> 3
        name_kind = field_map.get(field_id)
        if name_kind is not None:
            name, kind = name_kind
            if kind == "voltage":
                if field_id == 14 and _between(value, 60, 600):
                    out[name] = round(value / 10.0, 1)
                elif field_id == 14 and value == 0:
                    out[name] = 0
                elif field_id != 14 and _between(value, 0, 1000):
                    out[name] = float(value) if value else 0
            elif _between(value, 0, 3000):
                out[name] = value
        i += 4
    for prefix in ("usb_a1", "usb_a2", "usb_a3", "usb_a4", "typec_1", "typec_2", "dc12v", "dc24v"):
        voltage = out.get(f"{prefix}_voltage")
        power = out.get(f"{prefix}_power")
        if _between(voltage, 0.1, 1000) and power is not None:
            out[f"{prefix}_current"] = round(float(power) / float(voltage), 2)
        elif power == 0:
            out[f"{prefix}_current"] = 0.0
    if "dc12v_power" in out and "dc12v_voltage" not in out:
        out["dc12v_voltage"] = 13.7
        out["dc12v_current"] = round(float(out["dc12v_power"]) / 13.7, 2)
    return out


def _extract_bms_cell_data(payload: bytes, out: dict) -> None:
    marker_idx = payload.find(b"\x01\x54")
    if marker_idx < 0:
        return
    i = marker_idx + 2
    seen_fields: set = set()
    while i + 4 <= len(payload):
        tag = _u16(payload, i)
        if tag is None:
            break
        field_id = tag >> 3
        prefix = payload[i + 2]
        if (tag & 0x07) == 0x02 and 14 <= field_id <= 17 and prefix == 0x00:
            compact_value = _u16(payload, i + 2)
            if compact_value is None:
                break
            if field_id == 15 and _between(compact_value, 0, 10000):
                out["battery_cycles"] = compact_value
            elif field_id == 16 and _between(compact_value, 0, 300):
                out["bms_allow_max_charge_current"] = float(compact_value)
            elif field_id == 17 and _between(compact_value, 0, 65535):
                out["bms_mos_status"] = compact_value
            seen_fields.add(field_id)
            i += 4
            continue
        if i + 5 > len(payload):
            break
        value = _u16(payload, i + 3)
        if value is None:
            break
        if (tag & 0x07) == 0x02 and 1 <= field_id <= 17 and prefix in (0x00, 0x01, 0x80, 0x81):
            signed_value = -value if prefix & 0x80 else value
            if 1 <= field_id <= 13:
                if _between(value, 2500, 5000):
                    out[f"battery_cell_{field_id:02d}_voltage"] = round(value / 1000.0, 3)
            elif field_id == 15 and _between(signed_value, 0, 10000):
                out["battery_cycles"] = signed_value
            elif field_id == 16 and _between(signed_value, 0, 300):
                out["bms_allow_max_charge_current"] = float(signed_value)
            elif field_id == 17 and _between(signed_value, 0, 65535):
                out["bms_mos_status"] = signed_value
            seen_fields.add(field_id)
            i += 5
            continue
        if len(seen_fields) >= 4 and field_id > 17:
            break
        i += 1


def _dc_component_power(values: dict):
    keys = (
        "usb_a1_power", "usb_a2_power", "usb_a3_power", "usb_a4_power",
        "typec_1_power", "typec_2_power", "dc12v_power", "dc24v_power",
    )
    if not any(k in values for k in keys):
        return None
    return sum(float(values.get(k) or 0) for k in keys)


def decode_bus_payload(plain: bytes) -> dict:
    out: dict = {}
    payload = plain
    is_work_profile_frame = payload.startswith(b"\x01\x4c")
    _extract_bus_strings(payload, out)
    if "work_profile" in out:
        _parse_work_profile(out["work_profile"], out)
    _extract_output_power_set(payload, out)
    if is_work_profile_frame and len(payload) >= 14:
        bms_temp = _u16(payload, 6) if _u16(payload, 4) == 0x000A else None
        inv_temp = _u16(payload, 10) if _u16(payload, 8) == 0x0012 else None
        mppt_temp = _u16(payload, 14) if _u16(payload, 12) == 0x001A else None
        if _between(bms_temp, -40, 120):
            out["temp_bms"] = bms_temp
        if _between(inv_temp, -40, 160):
            out["temp_inv"] = inv_temp
        if _between(mppt_temp, -40, 160):
            out["temp_mppt"] = mppt_temp

    _extract_bms_cell_data(payload, out)

    # Struttura PV TTLV — confermata dai payload raw cloud (q/2/.../bus):
    #   [i+0..1]  \x00\x0c  struct tag pv_data
    #   [i+2..3]  \x00\x03  3 sub-field
    #   [i+4..5]  \x00\x0a  sub-tag1: pv_total_power
    #   [i+?..?]  \x00\x1a  sub-tag2: pv_1_voltage
    # Encoding per-field in base al valore:
    #   4-byte (val < 256): [tag 2B][val 2B]            — _u16
    #   5-byte (val >= 256): [tag 2B][prefix 1B][val 2B] — _s16_prefixed
    # sub-tag2 a +8: sub-field1 4-byte (potenza<256W); a +9: 5-byte (>=256W)
    # sub-tag3 (0x0022) a +12: sub-field2 4-byte (tensione in V); a +13: 5-byte (in deci-V)
    i_pv = payload.find(b"\x00\x0c\x00\x03\x00\x0a")
    if i_pv >= 0 and i_pv + 17 <= len(payload):
        volt_offset = None
        for _voff in (8, 9):
            if _u16(payload, i_pv + _voff) == 0x001a:
                volt_offset = _voff
                break
        if volt_offset == 8:
            # sub-field 1: 4-byte
            pv_power = _u16(payload, i_pv + 6)
            if _between(pv_power, 0, 3000):
                out["pv_input_power"] = pv_power
            if pv_power and pv_power > 0:
                if _u16(payload, i_pv + 12) == 0x0022:
                    # 4-byte: V diretti, range 5-80V
                    volt_raw = _u16(payload, i_pv + 10)
                    if _between(volt_raw, 5, 80):
                        out["pv_panel_voltage"] = float(volt_raw)
                elif _u16(payload, i_pv + 13) == 0x0022:
                    # 5-byte: deci-V (x10), range 50-800
                    volt_raw = _s16_prefixed(payload, i_pv + 10)
                    if _between(volt_raw, 50, 800):
                        out["pv_panel_voltage"] = round(volt_raw / 10.0, 1)
            else:
                # pv_power == 0: pubblica esplicitamente 0V per pulire il valore
                # retained in HA (senza questo HA mostra l'ultimo valore del giorno)
                out["pv_panel_voltage"] = 0.0
        elif volt_offset == 9 and i_pv + 19 <= len(payload):
            # sub-field 1: 5-byte
            pv_power = _s16_prefixed(payload, i_pv + 6)
            if _between(pv_power, 0, 3000):
                out["pv_input_power"] = pv_power
            if pv_power and pv_power > 0:
                volt_raw = _s16_prefixed(payload, i_pv + 11)
                if _between(volt_raw, 50, 800):
                    out["pv_panel_voltage"] = round(volt_raw / 10.0, 1)
            else:
                out["pv_panel_voltage"] = 0.0
        if _is_debug() and out.get("pv_input_power", 0) > 0 and "pv_panel_voltage" not in out:
            end = min(i_pv + 24, len(payload))
            _dprint(f"pv struct raw[{i_pv}..{end}]: {payload[i_pv:end].hex(' ')} "
                    f"volt_offset={volt_offset}")

    if payload.startswith(b"\x00\x70") and len(payload) >= 24:
        dc_power = _u16(payload, 22)
        if _between(dc_power, 0, 3000):
            out["dc_output_power"] = dc_power
    t6a = payload.find(b"\x00\x6a")
    if t6a >= 0:
        t6a2 = payload.find(b"\x00\x6a", t6a + 4)
        if t6a2 >= 0:
            dc = _u16(payload, t6a2 + 2)
            if _between(dc, 0, 6000):
                out["dc_output_power"] = round(dc / 2.0)
    out.update(_extract_dc_data(payload))

    idx = payload.find(b"\x00\x14\x00\x03\x00\x12")
    ac_idx = payload.find(b"\x00\x2c\x00\x02\x00\x12")

    def decode_ac_power_block(block_idx: int) -> bool:
        if block_idx < 0 or block_idx + 19 > len(payload):
            return False
        voltage_raw = _s16_prefixed(payload, block_idx + 6)
        voltage_u16 = _u16(payload, block_idx + 6)
        section = payload[block_idx:block_idx + 28]
        power_raw = _tag_prefixed_s16(section, b"\x00\x1a")
        power_u16 = _tag_u16(section, b"\x00\x1a")
        freq = _tag_u16(section, b"\x00\x22")
        if not _between(power_raw, -10000, 10000) and _between(power_u16, 0, 3000):
            power_raw = power_u16
        voltage = None
        if _between(voltage_raw, 1500, 2700):
            voltage = round(voltage_raw / 10.0, 1)
        elif _between(voltage_u16, 150, 270):
            voltage = float(voltage_u16)
        if voltage is None:
            return False
        if _between(freq, 45, 65):
            out["grid_freq"] = freq
        if _between(power_raw, -10000, 10000):
            out["grid_voltage"] = voltage
            if power_raw < 0:
                out["ac_input_power"] = abs(power_raw)
                out["ac_output_power"] = 0
                out["grid_b_power"] = 0
            else:
                out["grid_b_power"] = power_raw
                out["ac_output_power"] = power_raw
                out["ac_input_power"] = 0
        else:
            out["grid_voltage"] = voltage
        return True

    if ac_idx >= 0 and decode_ac_power_block(ac_idx):
        pass
    elif idx >= 0 and idx + 19 <= len(payload):
        if decode_ac_power_block(idx):
            pass
        else:
            voltage_raw = _s16_prefixed(payload, idx + 6)
            voltage_u16 = _u16(payload, idx + 6)
            if voltage_raw == 0 or voltage_u16 == 0:
                is_battery_frame = b"\x00\x24" in payload
                out.pop("grid_voltage", None)
                if not is_battery_frame:
                    out["grid_voltage"] = 0
                    out["grid_freq"] = 0
                    out["grid_b_power"] = 0
                    out["ac_input_power"] = 0
                    out["ac_output_power"] = 0
    elif payload.startswith(b"\x00\x70"):
        pass

    battery_block_idx = payload.find(b"\x00\x24")
    idx = payload.find(b"\x53\x30\x00\x12", battery_block_idx if battery_block_idx >= 0 else 0)
    if battery_block_idx >= 0 and idx >= 0:
        section = payload[idx:min(len(payload), idx + 56)]
        soc = _tag_u16(section, b"\x00\x12")
        remaining = _tag_prefixed_s16(section, b"\x00\x1a")
        if not _between(remaining, 0, 100000):
            remaining = _tag_u16(section, b"\x00\x1a")
        temp = _tag_u16(section, b"\x00\x3a")
        voltage_pref = _tag_prefixed_s16(section, b"\x00\x22")
        voltage_u16 = _tag_u16(section, b"\x00\x22")
        power_pref = _tag_battery_power_after(section, b"\x00\x32", b"\x00\x22")
        voltage = None
        if voltage_pref is not None:
            voltage = round(voltage_pref / 10.0, 1) if voltage_pref > 200 else float(voltage_pref)
        if not _between(voltage, 40.0, 70.0) and _between(voltage_u16, 40, 70):
            voltage = float(voltage_u16)
        if _between(soc, 0, 100) and _between(temp, -40, 120):
            out["battery_percentage"] = soc
            if remaining is not None:
                out["remaining_time_minutes"] = remaining
            out["battery_temp"] = temp
            if _between(voltage, 40.0, 70.0):
                out["battery_voltage"] = float(voltage)
                if _between(power_pref, -3000, 3000):
                    out["battery_total_power"] = power_pref
                    if abs(float(voltage)) > 0:
                        out["battery_current"] = round(power_pref / float(voltage), 2)

    _apply_battery_data_struct(payload, out)

    if any(k in out for k in ("pv_input_power", "ac_input_power")):
        out["total_input_power"] = round(float(out.get("pv_input_power") or 0) + float(out.get("ac_input_power") or 0), 2)
    if any(k in out for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
        out["total_output_power"] = calculate_total_output_power(out)
    hfr_tag = payload.find(b"\x00\x9A")
    if hfr_tag >= 0 and hfr_tag + 4 <= len(payload):
        hfr_labels = {
            0: "Infrequente",
            1: "LAN HFR",
            2: "WiFi HFR",
            3: "LAN+WiFi HFR",
        }
        hfr_val = payload[hfr_tag + 3]
        if hfr_val in hfr_labels:
            out["high_frequency_reporting"] = hfr_labels[hfr_val]
    if is_work_profile_frame:
        out.pop("battery_temp", None)
    return {k: v for k, v in out.items() if v is not None}


# ══════════════════════════════════════════════════════════════════════════════
# MQTT client (minimal, no external dependencies)
# ══════════════════════════════════════════════════════════════════════════════

def _mqtt_remaining_length(length):
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def _mqtt_string(value):
    data = value.encode("utf-8")
    return len(data).to_bytes(2, "big") + data


class MqttConnectionError(RuntimeError):
    """Raised for MQTT socket failures so they are not handled as LAN errors."""


class MqttClient:
    def __init__(self, host, port, username=None, password=None,
                 client_id="landbook_lan_bridge",
                 will_topic=None, will_payload=None, will_retain=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_id = client_id
        self.will_topic = will_topic
        self.will_payload = will_payload
        self.will_retain = will_retain
        self.sock = None
        self.rx = bytearray()
        self.next_packet_id = 1
        self._subscriptions = []

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        flags = 0x02
        payload = _mqtt_string(self.client_id)
        if self.will_topic is not None and self.will_payload is not None:
            flags |= 0x04
            if self.will_retain:
                flags |= 0x20
            wp = self.will_payload.encode("utf-8") if isinstance(self.will_payload, str) else self.will_payload
            payload += _mqtt_string(self.will_topic) + len(wp).to_bytes(2, "big") + wp
        if self.username is not None:
            flags |= 0x80
            payload += _mqtt_string(self.username)
        if self.password is not None:
            flags |= 0x40
            payload += _mqtt_string(self.password)
        variable = _mqtt_string("MQTT") + b"\x04" + bytes([flags]) + (60).to_bytes(2, "big")
        self.sock.sendall(b"\x10" + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        reply = self.sock.recv(4)
        if len(reply) < 4 or reply[0] != 0x20 or reply[3] != 0:
            raise RuntimeError(f"MQTT connect failed: {reply.hex(' ')}")
        self.sock.setblocking(False)

    def publish(self, topic, payload, retain=False):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        variable = _mqtt_string(topic)
        header = bytes([0x31 if retain else 0x30])
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(header + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        except OSError as exc:
            raise MqttConnectionError(f"MQTT publish failed: {exc}") from exc

    def reconnect(self):
        """Chiude (se serve) e ricrea la connessione MQTT da zero."""
        self._last_reconnect_attempt = time.time()
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.connect()
        if self._subscriptions:
            self._send_subscribe(self._subscriptions)

    def publish_resilient(self, topic, payload, retain=False):
        """Come publish(), ma se il socket MQTT è morto (broken pipe, ecc.)
        tenta di riconnettersi e ripubblicare prima di arrendersi.

        Il primo tentativo di reconnect dopo un publish falito è sempre
        immediato: un alert critico (es. wifi_frozen) deve poter riuscire già
        al primo giro. Il cooldown si applica solo ai tentativi successivi,
        per non sprecare handshake MQTT ripetuti quando il broker è giù da
        più tempo (es. più alert consecutivi durante la stessa interruzione)."""
        try:
            self.publish(topic, payload, retain=retain)
            return True
        except Exception:
            last_attempt = getattr(self, "_last_reconnect_attempt", 0.0)
            if time.time() - last_attempt < MQTT_RECONNECT_COOLDOWN:
                raise
            self.reconnect()
            self.publish(topic, payload, retain=retain)
            return True

    def _send_subscribe(self, topics):
        packet_id = self.next_packet_id
        self.next_packet_id += 1
        variable = packet_id.to_bytes(2, "big")
        payload = b"".join(_mqtt_string(t) + b"\x00" for t in topics)
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(b"\x82" + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        except OSError as exc:
            raise MqttConnectionError(f"MQTT subscribe failed: {exc}") from exc

    def subscribe(self, topics):
        topics = list(dict.fromkeys(t for t in topics if t))
        self._subscriptions = topics
        if not topics:
            return False
        self._send_subscribe(topics)
        return True

    def ping(self):
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(b"\xC0\x00")
        except OSError as exc:
            raise MqttConnectionError(f"MQTT ping failed: {exc}") from exc

    def disconnect(self):
        if self.sock is None:
            return
        try:
            self.sock.sendall(b"\xE0\x00")
        finally:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def read_messages(self):
        try:
            if self.sock is None:
                raise RuntimeError("MQTT disconnected")
            chunk = self.sock.recv(4096)
            if chunk:
                self.rx.extend(chunk)
            else:
                raise RuntimeError("MQTT disconnected")
        except BlockingIOError:
            pass
        except (OSError, RuntimeError) as exc:
            raise MqttConnectionError(f"MQTT disconnected: {exc}") from exc
        messages = []
        while True:
            if len(self.rx) < 2:
                return messages
            multiplier, value, pos = 1, 0, 1
            while True:
                if pos >= len(self.rx):
                    return messages
                byte = self.rx[pos]
                pos += 1
                value += (byte & 127) * multiplier
                if not byte & 128:
                    break
                multiplier *= 128
            end = pos + value
            if len(self.rx) < end:
                return messages
            retain = bool(self.rx[0] & 0x01)
            packet_type = self.rx[0] >> 4
            body = bytes(self.rx[pos:end])
            del self.rx[:end]
            if packet_type != 3 or len(body) < 2:
                continue
            topic_len = int.from_bytes(body[:2], "big")
            topic = body[2:2 + topic_len].decode("utf-8", errors="replace")
            payload = body[2 + topic_len:].decode("utf-8", errors="replace")
            messages.append((topic, payload, retain))


# ══════════════════════════════════════════════════════════════════════════════
# HA MQTT discovery
# ══════════════════════════════════════════════════════════════════════════════

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


def _socket_cloud():
    """Return the cloud session manager for smart sockets, or None.

    Isolated in wf_socket_cloud so the powerstation LAN path stays untouched:
    this owns the cloud access-token refresh and the live device list.
    """
    try:
        from wf_socket_cloud import get_cloud
    except Exception as exc:
        print(f"[socket-cloud] modulo non disponibile: {exc}", flush=True)
        return None
    return get_cloud()


def _normalize_auth_header(token: str) -> str:
    token = str(token or "").strip()
    if not token:
        return ""
    return token if token.lower().startswith("bearer ") else f"Bearer {token}"


def _cloud_base_url(discovered: dict) -> str:
    base = str(discovered.get("base_url") or "").strip()
    if base:
        return base.rstrip("/")
    platform = str(discovered.get("_platform") or "").strip()
    for path in (PLATFORMS_PATH, os.path.join(os.path.dirname(__file__), "platforms.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                platforms = json.load(fh) or {}
            cfg = platforms.get(platform) or {}
            base = str(cfg.get("base_url") or "").strip()
            if base:
                return base.rstrip("/")
        except Exception:
            pass
    return ""


def _cloud_accel_url(discovered: dict) -> str:
    accel_url = str(discovered.get("accel_url") or "").strip()
    if accel_url:
        return accel_url
    platform = str(discovered.get("_platform") or "").strip()
    for path in (PLATFORMS_PATH, os.path.join(os.path.dirname(__file__), "platforms.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                platforms = json.load(fh) or {}
            cfg = platforms.get(platform) or {}
            accel_url = str(cfg.get("accel_url") or "").strip()
            if accel_url:
                return accel_url
        except Exception:
            pass
    return ""


def _smart_socket_devices(args) -> list:
    if not getattr(args, "smart_sockets_enabled", True):
        return []
    data = _load_discovered_cache()
    devices = data.get("smart_socket_devices") or []
    out = []

    def add_socket(dk: str, pk: str, name: str = "", product_name: str = "Smart socket"):
        dk = str(dk or "").strip()
        pk = str(pk or "").strip()
        if not dk or pk.lower() not in SMART_SOCKET_PRODUCT_KEYS:
            return
        if any(existing["device_key"] == dk for existing in out):
            return
        out.append({
            "device_key": dk,
            "product_key": pk,
            "name": str(name or dk),
            "product_name": str(product_name or "Smart socket"),
        })

    for dev in devices:
        if not isinstance(dev, dict):
            continue
        pk = str(dev.get("product_key") or dev.get("productKey") or "").strip()
        dk = str(dev.get("device_key") or dev.get("deviceKey") or "").strip()
        add_socket(
            dk,
            pk,
            str(dev.get("name") or dev.get("deviceName") or dk),
            str(dev.get("product_name") or dev.get("productName") or "Smart socket"),
        )
    # La lista auto-rilevata dal cloud (smart_socket_devices in cache) è
    # autoritativa: le prese vengono scoperte da sole e, se eliminate dall'app,
    # spariscono. Le chiavi statiche in config e i fallback interni servono solo
    # come rete di sicurezza quando il cloud non ha ancora popolato la cache
    # (primo avvio offline / credenziali assenti) — altrimenti riaggiungerebbero
    # una presa appena rimossa.
    if not out:
        for idx in (1, 2):
            add_socket(
                getattr(args, f"smart_socket_{idx}_device_key", ""),
                getattr(args, f"smart_socket_{idx}_product_key", ""),
                getattr(args, f"smart_socket_{idx}_name", ""),
            )
        for dev in SMART_SOCKET_FALLBACK_DEVICES:
            add_socket(
                dev.get("device_key", ""),
                dev.get("product_key", ""),
                dev.get("name", ""),
                dev.get("product_name", "Smart socket"),
            )
    return out


def _smart_socket_device_by_key(args, device_key: str):
    wanted = str(device_key or "").strip()
    for dev in _smart_socket_devices(args):
        if dev["device_key"] == wanted:
            return dev
    return None


def _smart_socket_bus_topics(socket_dev: dict) -> list:
    pk = socket_dev["product_key"]
    dk = socket_dev["device_key"]
    return [
        f"q/1/d/qd{pk}{dk}/bus",
        f"q/2/d/qd{pk}{dk}/bus",
        f"q/1/d/qd/{pk}/{dk}/bus",
        f"q/2/d/qd/{pk}/{dk}/bus",
    ]


def _smart_socket_frame(args, device_key: str, on: bool) -> bytes:
    raw = SMART_SOCKET_ON_HEX if on else SMART_SOCKET_OFF_HEX
    frame = bytearray(bytes.fromhex(raw.replace(" ", "")))
    seqs = getattr(args, "_smart_socket_seq", None)
    if not isinstance(seqs, dict):
        seqs = {}
    seq = int(seqs.get(device_key, int(time.time() * 1000) & 0xFF))
    seq = (seq + 1) & 0xFF
    seqs[device_key] = seq
    args._smart_socket_seq = seqs
    if len(frame) >= 7:
        frame[6] = seq
    return bytes(frame)


def _publish_smart_socket_cloud_command(socket_dev: dict, payload: bytes, discovered: dict) -> None:
    token = str(discovered.get("token") or "").strip()
    accel_url = _cloud_accel_url(discovered)
    accel_client = str(discovered.get("accel_client") or "").strip()
    if not token or not accel_url:
        raise RuntimeError("token o accel_url mancanti per comando smart socket")
    parsed = urllib.parse.urlparse(accel_url)
    if parsed.scheme not in ("ws", "wss"):
        raise RuntimeError(f"accel_url non valido: {accel_url}")

    try:
        import paho.mqtt.client as paho_mqtt
    except Exception as exc:
        raise RuntimeError("py3-paho-mqtt non installato") from exc

    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/ws/v2"
    prefix = accel_client if accel_client else "qu_landbook_"
    if not prefix.endswith("_"):
        prefix += "_"
    client_id = f"{prefix}{int(time.time() * 1000)}"

    cli = paho_mqtt.Client(client_id=client_id, transport="websockets", protocol=paho_mqtt.MQTTv311)
    cli.username_pw_set(username="", password=_normalize_auth_header(token))
    cli.ws_set_options(path=path)
    if parsed.scheme == "wss":
        cli.tls_set()
    cli.connect(host, port, keepalive=25)
    cli.loop_start()
    try:
        for topic in _smart_socket_bus_topics(socket_dev):
            info = cli.publish(topic, payload=payload, qos=1, retain=False)
            info.wait_for_publish(timeout=5)
            if info.rc != paho_mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"publish cloud fallito rc={info.rc} topic={topic}")
    finally:
        cli.loop_stop()
        cli.disconnect()


def _handle_smart_socket_command(topic, payload, mqtt, base_topic, args) -> bool:
    prefix = f"{base_topic}/smart_sockets/"
    suffix = "/set/switch"
    if not topic.startswith(prefix) or not topic.endswith(suffix):
        return False
    dk = topic[len(prefix):-len(suffix)]
    socket_dev = _smart_socket_device_by_key(args, dk)
    if not socket_dev:
        print(f"smart socket command ignored: unknown device {dk}", flush=True)
        return True
    state = payload.strip().upper()
    if state not in ("ON", "OFF"):
        return True
    if not _command_tx_allowed(args, f"smart_socket_{dk}", state, opposite_window=0.5):
        return True
    frame = _smart_socket_frame(args, dk, state == "ON")
    discovered = _load_discovered_cache()
    # Usa un token cloud fresco anche per il comando (altrimenti dopo la scadenza
    # lo switch smetterebbe di rispondere, come i sensori).
    cloud = _socket_cloud()
    if cloud is not None and cloud.available():
        try:
            fresh = cloud.ensure_token()
            if fresh:
                discovered["token"] = fresh
        except Exception as exc:
            print(f"smart socket token refresh failed {dk}: {exc}", flush=True)
    try:
        _publish_smart_socket_cloud_command(socket_dev, frame, discovered)
    except Exception as exc:
        print(f"smart socket command failed {dk}: {exc}", flush=True)
        return True
    mqtt.publish(f"{base_topic}/smart_sockets/{dk}/switch", state, retain=True)
    print(f"sent smart socket {dk} {state}", flush=True)
    return True


def _request_json(url: str, params: dict, token: str) -> dict:
    query = urllib.parse.urlencode(params)
    full_url = url + ("?" + query if query else "")
    req = urllib.request.Request(
        full_url,
        headers={
            "Accept": "application/json",
            "Authorization": _normalize_auth_header(token),
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _fetch_socket_attrs(discovered: dict, socket_dev: dict) -> dict:
    base_url = _cloud_base_url(discovered)
    token = str(discovered.get("token") or "").strip()
    if not base_url or not token:
        return {}
    j = _request_json(
        base_url + "/v2/binding/enduserapi/getDeviceBusinessAttributes",
        {"dk": socket_dev["device_key"], "pk": socket_dev["product_key"]},
        token,
    )
    if j.get("code") != 200:
        return {}
    data = j.get("data") or {}
    attrs = data.get("customizeTslInfo") or []
    out = {}
    for item in attrs:
        if not isinstance(item, dict):
            continue
        code = str(item.get("resourceCode") or "")
        value = item.get("resourceValce")
        if code == "switch":
            out["switch"] = "ON" if _boolish(value) else "OFF"
        elif code == "electricity_data":
            try:
                out["energy"] = round(float(value) / 1000.0, 3)
            except (TypeError, ValueError):
                pass
        elif code == "measure_data":
            try:
                measure = json.loads(value) if isinstance(value, str) else (value or {})
            except Exception:
                measure = {}
            try:
                voltage = round(float(measure.get("voltage_values") or 0) / 1000.0, 3)
                out["voltage"] = voltage
            except (TypeError, ValueError):
                voltage = None
                pass
            try:
                power = round(float(measure.get("power_value") or 0) / 1000.0, 3)
                out["power"] = power
            except (TypeError, ValueError):
                power = None
                pass
            try:
                current = round(float(measure.get("current_value") or 0) / 1000.0, 3)
                out["current"] = current
            except (TypeError, ValueError):
                current = None
                pass
            if voltage is not None and current is not None:
                apparent = round(float(voltage) * float(current), 3)
                out["apparent_power"] = apparent
                if apparent > 1 and power is not None:
                    out["power_factor"] = round(float(power) / apparent, 3)
                else:
                    out["power_factor"] = 0
    return out


def _fetch_socket_online_status(discovered: dict) -> dict | None:
    base_url = _cloud_base_url(discovered)
    token = str(discovered.get("token") or "").strip()
    if not base_url or not token:
        return None
    try:
        j = _request_json(
            base_url + "/v2/binding/enduserapi/userDeviceList",
            {"pageSize": 50, "isAssociated": 1},
            token,
        )
    except Exception as exc:
        _dprint(f"smart socket online status failed: {exc}", flush=True)
        return None
    if j.get("code") != 200:
        return None
    items = (j.get("data") or {}).get("list") or []
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        dk = str(item.get("deviceKey") or item.get("device_key") or "").strip()
        if not dk:
            continue
        try:
            out[dk] = int(item.get("onlineStatus", 0) or 0) == 1
        except Exception:
            out[dk] = _boolish(item.get("onlineStatus"))
    return out


def _socket_liveness_topic(base_topic: str) -> str:
    """Topic di 'bridge vivo' DEDICATO alle prese, del tutto separato dalla
    availability della powerstation. Ha il proprio Last Will (vedi
    _start_socket_liveness): va offline solo quando il processo add-on si spegne,
    NON quando la powerstation ha problemi LAN/freeze."""
    return f"{base_topic}/smart_sockets/bridge_availability"


def _start_socket_liveness(args):
    """Connessione MQTT SEPARATA, dedicata solo alle prese, il cui unico scopo è
    tenere un Last Will sul topic di liveness delle prese.

    È del tutto indipendente dalla connessione/availability della powerstation:
    quando il processo add-on muore (stop o crash), il broker pubblica da solo
    'offline' su questo topic → le prese diventano non disponibili in HA. Un
    problema LAN/freeze della powerstation non passa da qui, quindi non tocca le
    prese. Ritorna il client (da tenere referenziato) o None."""
    if not getattr(args, "smart_sockets_enabled", True):
        return None
    try:
        import paho.mqtt.client as paho_mqtt
    except Exception as exc:
        print(f"[socket-cloud] liveness non attiva (paho assente): {exc}", flush=True)
        return None
    topic = _socket_liveness_topic(args.topic)
    cli = paho_mqtt.Client(
        client_id=f"landbook_sock_live_{int(time.time() * 1000)}",
        protocol=paho_mqtt.MQTTv311,
    )
    if getattr(args, "mqtt_user", ""):
        cli.username_pw_set(args.mqtt_user, getattr(args, "mqtt_password", "") or "")
    cli.will_set(topic, "offline", qos=1, retain=True)

    def _on_connect(client, userdata, flags, rc, *a):
        # Ripubblica 'online' a ogni (ri)connessione della connessione dedicata.
        client.publish(topic, "online", qos=1, retain=True)

    cli.on_connect = _on_connect
    try:
        cli.reconnect_delay_set(min_delay=1, max_delay=30)
    except Exception:
        pass
    try:
        cli.connect(args.mqtt_host, int(args.mqtt_port), keepalive=30)
    except Exception as exc:
        print(f"[socket-cloud] liveness connect fallita: {exc}", flush=True)
        return None
    cli.loop_start()
    print(f"[socket-cloud] liveness prese attiva su {topic}", flush=True)
    return cli


def _stop_socket_liveness(args) -> None:
    """Chiude in modo PULITO la connessione liveness prese (DISCONNECT esplicito,
    niente Will) mantenendo il retained 'online'. Da chiamare prima di un
    os.execv, così un self-restart del bridge (es. freeze powerstation) NON manda
    le prese offline."""
    cli = getattr(args, "_socket_liveness", None)
    if cli is None:
        return
    args._socket_liveness = None
    try:
        cli.publish(_socket_liveness_topic(args.topic), "online", qos=1, retain=True)
    except Exception:
        pass
    try:
        cli.disconnect()   # DISCONNECT pulito → il broker NON pubblica il Will
    except Exception:
        pass
    try:
        cli.loop_stop()
    except Exception:
        pass


def _restart_process(args) -> None:
    """Self-restart del bridge preservando lo stato 'online' delle prese."""
    _stop_socket_liveness(args)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def _publish_smart_socket_discovery(mqtt, base_topic, args):
    parent_key = _device_key(args)
    socket_liveness_topic = _socket_liveness_topic(base_topic)
    socket_devices = _smart_socket_devices(args)
    total_device = {
        "identifiers": [parent_key],
        "name": DEVICE_NAME,
        "manufacturer": "Landbook",
        "model": os.environ.get("PRODUCT_KEY") or "TSL LAN device",
        "serial_number": parent_key,
    }
    total_cfg = {
        "name": "Smart socket total power",
        "object_id": f"{DEVICE_OBJECT_ID}_smart_socket_total_power",
        "has_entity_name": True,
        "state_topic": f"{base_topic}/smart_sockets/total_power",
        "unit_of_measurement": "W",
        "device_class": "power",
        "state_class": "measurement",
        "force_update": True,
        "unique_id": f"{parent_key}_smart_socket_total_power",
        "device": total_device,
        "availability_topic": socket_liveness_topic,
        "payload_available": "online",
        "payload_not_available": "offline",
    }
    mqtt.publish(f"homeassistant/sensor/{parent_key}/smart_socket_total_power/config", json.dumps(total_cfg), retain=True)

    for dev in socket_devices:
        dk = dev["device_key"]
        socket_availability_topic = f"{base_topic}/smart_sockets/{dk}/availability"
        # Doppia disponibilità in modalità "all": la presa è disponibile solo se
        # SIA il bridge è vivo (topic di liveness DEDICATO alle prese, con Last
        # Will proprio → offline solo se l'add-on si spegne, indipendente dalla
        # powerstation) SIA la presa è online sul cloud. Così spegnendo il bridge
        # le prese vanno offline, ma un freeze/outage LAN della powerstation NON
        # le tocca, e resta il rilevamento della singola presa scollegata.
        socket_availability = [
            {"topic": socket_liveness_topic,
             "payload_available": "online", "payload_not_available": "offline"},
            {"topic": socket_availability_topic,
             "payload_available": "online", "payload_not_available": "offline"},
        ]
        slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in dk).strip("_")
        socket_name = str(dev.get("name") or dk)
        device = {
            "identifiers": [f"wonderfree_socket_{dk}"],
            "name": socket_name,
            "manufacturer": "Wonderfree",
            "model": dev.get("product_name") or dev.get("product_key") or "Smart socket",
            "serial_number": dk,
            "via_device": parent_key,
        }
        mqtt.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
        mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
        switch_cfg = {
            "name": "Switch",
            "object_id": f"wonderfree_socket_{slug}_device_switch",
            "has_entity_name": True,
            "state_topic": f"{base_topic}/smart_sockets/{dk}/switch",
            "command_topic": f"{base_topic}/smart_sockets/{dk}/set/switch",
            "payload_on": "ON",
            "payload_off": "OFF",
            "stat_t": f"{base_topic}/smart_sockets/{dk}/switch",
            "cmd_t": f"{base_topic}/smart_sockets/{dk}/set/switch",
            "pl_on": "ON",
            "pl_off": "OFF",
            "optimistic": False,
            "icon": "mdi:power-socket-eu",
            "unique_id": f"wonderfree_socket_{dk}_device_switch",
            "device": device,
            "availability": socket_availability,
            "availability_mode": "all",
        }
        mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", json.dumps(switch_cfg), retain=True)
        for sid, (name, unit, device_class, state_class) in SMART_SOCKET_SENSOR_DEFS.items():
            mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
            cfg = {
                "name": name,
                "object_id": f"wonderfree_socket_{slug}_device_{sid}",
                "has_entity_name": True,
                "state_topic": f"{base_topic}/smart_sockets/{dk}/{sid}",
                "unique_id": f"wonderfree_socket_{dk}_device_{sid}",
                "force_update": True,
                "device": device,
                "availability": socket_availability,
                "availability_mode": "all",
            }
            if unit:
                cfg["unit_of_measurement"] = unit
            if device_class:
                cfg["device_class"] = device_class
            if state_class:
                cfg["state_class"] = state_class
            mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", json.dumps(cfg), retain=True)
        mqtt.publish(socket_availability_topic, b"", retain=True)
    print(f"Smart socket discovery published: {len(socket_devices)}", flush=True)


def _remove_smart_socket_from_ha(mqtt, base_topic, dk) -> None:
    """Il device è stato eliminato dall'app: rimuovi le sue entità da HA
    pubblicando config vuote retained (HA le cancella da solo)."""
    mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", b"", retain=True)
    mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
    mqtt.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
    for sid in SMART_SOCKET_SENSOR_DEFS:
        mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", b"", retain=True)
        mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
    mqtt.publish(f"{base_topic}/smart_sockets/{dk}/availability", "offline", retain=True)


def _sync_smart_sockets_from_cloud(mqtt, base_topic, args, raw_devices) -> dict:
    """Allinea l'insieme delle prese alla device-list cloud (live).

    - Nuove prese → discovery HA + aggiunta in cache.
    - Prese assenti da >= SMART_SOCKET_NOT_FOUND_LIMIT poll → rimosse da HA e cache.
    Ritorna {device_key: online(bool)} dalla lista live.
    """
    from wf_socket_cloud import extract_sockets
    live = extract_sockets(raw_devices or [])
    live_by_dk = {d["device_key"]: d for d in live if d.get("device_key")}

    data = _load_discovered_cache()
    known = {
        d.get("device_key"): d
        for d in (data.get("smart_socket_devices") or [])
        if isinstance(d, dict) and d.get("device_key")
    }

    nf = getattr(args, "_socket_not_found", None)
    if not isinstance(nf, dict):
        nf = {}

    added = [dev for dk, dev in live_by_dk.items() if dk not in known]
    for dk in live_by_dk:
        nf.pop(dk, None)

    removed = []
    for dk in list(known):
        if dk not in live_by_dk:
            nf[dk] = nf.get(dk, 0) + 1
            print(f"[socket-cloud] {dk} assente dalla device-list "
                  f"({nf[dk]}/{SMART_SOCKET_NOT_FOUND_LIMIT})", flush=True)
            if nf[dk] >= SMART_SOCKET_NOT_FOUND_LIMIT:
                removed.append(dk)
    args._socket_not_found = nf

    if added or removed:
        new_set = []
        for dk, dev in live_by_dk.items():
            new_set.append({
                "device_key": dev.get("device_key", ""),
                "product_key": dev.get("product_key", ""),
                "name": dev.get("name", ""),
                "product_name": dev.get("product_name", "Smart socket"),
            })
        # Conserva le prese ancora nel periodo di grazia (assenti ma non oltre soglia).
        for dk, dev in known.items():
            if dk not in live_by_dk and dk not in removed:
                new_set.append(dev)
        data["smart_socket_devices"] = new_set
        _save_discovered_cache(data)

    if added:
        print(f"[socket-cloud] nuove prese rilevate: {[d['device_key'] for d in added]}", flush=True)
        _publish_smart_socket_discovery(mqtt, base_topic, args)
    for dk in removed:
        _remove_smart_socket_from_ha(mqtt, base_topic, dk)
        nf.pop(dk, None)
        print(f"[socket-cloud] presa {dk} eliminata dall'app — rimossa da HA", flush=True)

    return {dk: bool(dev.get("online")) for dk, dev in live_by_dk.items()}


def _poll_smart_sockets(mqtt, base_topic, args) -> None:
    if not getattr(args, "smart_sockets_enabled", True):
        return
    discovered = _load_discovered_cache()
    online_map = None
    used_cloud = False

    cloud = _socket_cloud()
    if cloud is not None and cloud.available():
        used_cloud = True
        try:
            token = cloud.ensure_token()
            if token:
                discovered["token"] = token
        except Exception as exc:
            _dprint(f"[socket-cloud] token refresh fallito: {exc}", flush=True)
        raw = cloud.list_devices()
        if raw is not None:
            # Device-list ok → auto-detect + rimozioni + mappa online live.
            online_map = _sync_smart_sockets_from_cloud(mqtt, base_topic, args, raw)
        # raw None = errore transitorio: online_map resta None → "assume online",
        # non tocchiamo le entità (come faceva il vecchio addon).

    if not used_cloud:
        # Nessuna credenziale / modulo assente: comportamento legacy.
        online_map = _fetch_socket_online_status(discovered)

    devices = _smart_socket_devices(args)
    if not devices:
        return
    total_power = 0.0
    any_power = False
    for dev in devices:
        dk = dev["device_key"]
        if online_map is not None:
            online = bool(online_map.get(dk, False))
            mqtt.publish(
                f"{base_topic}/smart_sockets/{dk}/availability",
                "online" if online else "offline",
                retain=True,
            )
            if not online:
                continue
        try:
            values = _fetch_socket_attrs(discovered, dev)
        except Exception as exc:
            _dprint(f"smart socket poll failed for {dev.get('device_key')}: {exc}", flush=True)
            continue
        if online_map is None and values:
            mqtt.publish(f"{base_topic}/smart_sockets/{dk}/availability", "online", retain=True)
        for key, value in values.items():
            mqtt.publish(f"{base_topic}/smart_sockets/{dk}/{key}", str(value), retain=True)
        if "power" in values:
            any_power = True
            total_power += float(values.get("power") or 0)
    if any_power:
        mqtt.publish(f"{base_topic}/smart_sockets/total_power", str(round(total_power, 3)), retain=True)


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


def publish_discovery(mqtt, base_topic, args):
    device_key = _device_key(args)
    device = {
        "identifiers": [device_key],
        "name": DEVICE_NAME,
        "manufacturer": "Landbook",
        "model": os.environ.get("PRODUCT_KEY") or "TSL LAN device",
        "serial_number": device_key,
    }
    # Clean up any stale/obsolete sensor configs
    for sensor_id in ["output_power_set_guess", "soc_guess", "battery_cell_14_voltage",
                      "device_status_raw", "remaining_time_days", "pv_panel_power"]:
        mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", b"", retain=True)
    # Clean up entities that earlier add-on versions auto-discovered from the TSL
    # but that we now know are duplicates, wrong type, or internal/diagnostic.
    try:
        from landbook_tsl_discovery import RETAINED_SWITCH_CLEANUP, RETAINED_SENSOR_CLEANUP, RETAINED_SELECT_CLEANUP
    except ImportError:
        RETAINED_SWITCH_CLEANUP, RETAINED_SENSOR_CLEANUP, RETAINED_SELECT_CLEANUP = [], [], []
    for sw_id in RETAINED_SWITCH_CLEANUP:
        mqtt.publish(f"homeassistant/switch/{device_key}/{sw_id}/config", b"", retain=True)
    for sn_id in RETAINED_SENSOR_CLEANUP:
        mqtt.publish(f"homeassistant/sensor/{device_key}/{sn_id}/config", b"", retain=True)
    for select_id in RETAINED_SELECT_CLEANUP:
        mqtt.publish(f"homeassistant/select/{device_key}/{select_id}/config", b"", retain=True)
    # Compatibility cleanup for versions that temporarily replaced baseline
    # switches with selects.
    for sw_id in _BASELINE_SHADOWED_BY_SELECT:
        mqtt.publish(f"homeassistant/switch/{device_key}/{sw_id}/config", b"", retain=True)
    if RETAINED_SWITCH_CLEANUP or RETAINED_SENSOR_CLEANUP or RETAINED_SELECT_CLEANUP or _BASELINE_SHADOWED_BY_SELECT:
        print(f"[discovery] cleared retained config for "
              f"{len(RETAINED_SWITCH_CLEANUP) + len(_BASELINE_SHADOWED_BY_SELECT)} switches + "
              f"{len(RETAINED_SENSOR_CLEANUP)} sensors + "
              f"{len(RETAINED_SELECT_CLEANUP)} selects", flush=True)
    if not args.show_firmware_sensors:
        for sensor_id in FIRMWARE_SENSOR_IDS:
            mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", b"", retain=True)

    # Sensors are TSL-first but observed-only: clear retained configs at startup,
    # then publish each sensor config only when a LAN report carries a real value.
    # This avoids dozens of "Sconosciuto" sensors for cloud-only or unsupported
    # TSL fields.
    for sensor_id in SENSOR_DEFS:
        mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", b"", retain=True)
    _PUBLISHED_SENSOR_CONFIGS.clear()

    for switch_id, switch in SWITCH_HEX.items():
        sw_object_id = f"{DEVICE_OBJECT_ID}_{SWITCH_OBJECT_ID_OVERRIDES.get(switch_id, switch_id)}"
        config = {
            "name": switch["name"],
            "object_id": sw_object_id,
            "has_entity_name": True,
            "command_topic": f"{base_topic}/set/{switch_id}",
            "state_topic": f"{base_topic}/cmd_state/{switch_id}",
            "payload_on": "ON", "payload_off": "OFF",
            "state_on": "ON", "state_off": "OFF",
            "optimistic": False,
            "unique_id": f"{device_key}_{switch_id}",
            "device": device,
            "availability_topic": f"{base_topic}/availability",
        }
        # Hardcoded meta wins (curated icons); TSL-inferred icons fill the gaps
        # for switches we haven't customized yet (e.g. heater_switch on a new model).
        meta = dict(_tsl_switch_meta.get(switch_id, {}))
        meta.update(SWITCH_DISCOVERY_META.get(switch_id, {}))
        config.update(meta)
        mqtt.publish(f"homeassistant/switch/{device_key}/{switch_id}/config", json.dumps(config), retain=True)

    # TSL-driven dynamic selects: every writable ENUM control becomes a HA select
    # with the cloud official labels. No model-specific select is invented here.
    try:
        from landbook_tsl_discovery import build_select_overlay as _build_select_overlay
        _tsl_select_overlay = _build_select_overlay(existing_switch_codes=set(SWITCH_HEX.keys()))
    except Exception as _exc:
        print(f"[tsl_discovery] select overlay skipped: {_exc}", flush=True)
        _tsl_select_overlay = {}
    for select_id, info in _tsl_select_overlay.items():
        opts = info.get("options") or {}
        if not opts:
            continue
        labels = [opts[k] for k in sorted(opts.keys())]
        mqtt.publish(f"homeassistant/select/{device_key}/{select_id}/config", json.dumps({
            "name": info.get("name") or select_id,
            "object_id": f"{DEVICE_OBJECT_ID}_{select_id}",
            "has_entity_name": True,
            "command_topic": f"{base_topic}/set/{select_id}",
            "state_topic": f"{base_topic}/cmd_state/{select_id}",
            "options": labels,
            "optimistic": False,
            "unique_id": f"{device_key}_{select_id}",
            "device": device,
            "availability_topic": f"{base_topic}/availability",
        }), retain=True)
    args._tsl_select_catalog = _tsl_select_overlay
    if _tsl_select_overlay:
        print(f"[tsl_discovery] dynamic selects published: {sorted(_tsl_select_overlay.keys())}",
              flush=True)

    # TSL-driven dynamic numbers: every writable numeric control becomes a HA number.
    try:
        from landbook_tsl_discovery import build_number_overlay as _build_number_overlay
        _tsl_number_overlay = _build_number_overlay()
    except Exception as _exc:
        print(f"[tsl_discovery] number overlay skipped: {_exc}", flush=True)
        _tsl_number_overlay = {}
    for number_id, info in _tsl_number_overlay.items():
        min_value = info.get("min")
        max_value = info.get("max")
        step = info.get("step") or 1
        cfg = {
            "name": info.get("name") or number_id,
            "object_id": f"{DEVICE_OBJECT_ID}_{number_id}",
            "has_entity_name": True,
            "command_topic": f"{base_topic}/set/{number_id}",
            "state_topic": f"{base_topic}/cmd_state/{number_id}",
            "step": step,
            "mode": "slider",
            "optimistic": False,
            "unique_id": f"{device_key}_{number_id}",
            "device": device,
            "availability_topic": f"{base_topic}/availability",
        }
        if min_value is not None:
            cfg["min"] = min_value
        if max_value is not None:
            cfg["max"] = max_value
        mqtt.publish(f"homeassistant/number/{device_key}/{number_id}/config", json.dumps(cfg), retain=True)
    args._tsl_number_catalog = _tsl_number_overlay
    if _tsl_number_overlay:
        print(f"[tsl_discovery] dynamic numbers published: {sorted(_tsl_number_overlay.keys())}",
              flush=True)

    mqtt.publish(f"homeassistant/number/{device_key}/{INTELLIGENT_CHARGING_POWER_ID}/config", json.dumps({
        "name": "Intelligent Charging Power",
        "object_id": f"{DEVICE_OBJECT_ID}_{INTELLIGENT_CHARGING_POWER_ID}",
        "has_entity_name": True,
        "command_topic": f"{base_topic}/set/{INTELLIGENT_CHARGING_POWER_ID}",
        "state_topic": f"{base_topic}/cmd_state/{INTELLIGENT_CHARGING_POWER_ID}",
        "min": min(INTELLIGENT_CHARGING_WATTS),
        "max": max(INTELLIGENT_CHARGING_WATTS),
        "step": 200,
        "mode": "slider",
        "unit_of_measurement": "W",
        "optimistic": False,
        "unique_id": f"{device_key}_{INTELLIGENT_CHARGING_POWER_ID}",
        "device": device,
        "availability_topic": f"{base_topic}/availability",
    }), retain=True)
    _publish_smart_socket_discovery(mqtt, base_topic, args)
    _dprint(f"published discovery {APP_VERSION}", flush=True)


def subscribe_command_topics(mqtt, base_topic, args=None):
    topics = [f"{base_topic}/set/{switch_id}" for switch_id in SWITCH_HEX]
    if args is not None:
        for select_id in (getattr(args, "_tsl_select_catalog", {}) or {}):
            topics.append(f"{base_topic}/set/{select_id}")
        number_catalog = getattr(args, "_tsl_number_catalog", {}) or {}
        for number_id in number_catalog:
            topics.append(f"{base_topic}/set/{number_id}")
        # Compatibility with old retained HA entities that used /set/output_power.
        if "output_power_set" in number_catalog:
            topics.append(f"{base_topic}/set/output_power")
        topics.append(f"{base_topic}/set/{INTELLIGENT_CHARGING_POWER_ID}")
        for dev in _smart_socket_devices(args):
            topics.append(f"{base_topic}/smart_sockets/{dev['device_key']}/set/switch")
    if not topics:
        print("no MQTT command topics to subscribe; TSL controls are empty", flush=True)
        return False
    mqtt.subscribe(topics)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Frame building & sending
# ══════════════════════════════════════════════════════════════════════════════

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


def _boolish(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "on", "yes", "y")


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

SWITCH_CACHE_PATH = "/data/landbook_switch_cache.json"


def cleanup_disabled_cache_files(args):
    for path in (getattr(args, "battery_cache_path", "") or "", SWITCH_CACHE_PATH):
        if not path:
            continue
        try:
            if os.path.exists(path):
                os.remove(path)
                _dprint(f"removed disabled cache file: {path}", flush=True)
        except Exception as exc:
            _dprint(f"cache file cleanup failed ({path}): {exc}", flush=True)


def publish_wifi_frozen_alert(mqtt, topic, *, reason, streak=None, duration=None):
    messages = {
        "sensor_silence": "PowerStation WiFi/LAN reporting frozen. Riavviare il WiFi del router o la powerstation.",
    }
    payload = {
        "reason": reason,
        "ts": int(time.time()),
        "message": messages.get(reason, "PowerStation WiFi/LAN reporting frozen. Riavviare il WiFi del router o la powerstation."),
    }
    if streak is not None:
        payload["streak"] = int(streak)
    if duration is not None:
        payload["duration"] = int(duration)
    mqtt.publish_resilient(f"{topic}/event/wifi_frozen", json.dumps(payload), retain=False)


# ══════════════════════════════════════════════════════════════════════════════
# Sensor publishing
# ══════════════════════════════════════════════════════════════════════════════

def _sensor_value(key, value):
    if key == "remaining_time_minutes":
        try:
            text = str(value).strip().lower()
            if "min" in text:
                minutes = int(float(text.split("min", 1)[0].strip()))
            else:
                minutes = int(float(value))
        except (TypeError, ValueError):
            return value
        days, rem = divmod(max(minutes, 0), 1440)
        hours, mins = divmod(rem, 60)
        if days:
            if hours and mins:
                return f"{days}g {hours}h {mins}min"
            if hours:
                return f"{days}g {hours}h"
            return f"{days}g"
        if hours and mins:
            return f"{hours}h {mins}min"
        if hours:
            return f"{hours}h"
        return f"{mins}min"
    return value


def _humanize_sensor_id(sensor_id: str) -> str:
    overrides = {
        "battery_percentage": "Battery",
        "battery_remaining_wh": "Battery Remaining",
        "battery_total_power": "Battery Power",
        "grid_b_power": "Grid AC Power",
        "grid_freq": "Grid Frequency",
        "remaining_time_minutes": "Tempo residuo",
        "uptime_minutes_lan": "HMI Field1 (uptime? non confermato)",
        "hmi_field1_raw": "HMI Field1 Raw",
        "hmi_field2_uptime_candidate": "Uptime Minutes (candidato)",
    }
    if sensor_id in overrides:
        return overrides[sensor_id]
    return " ".join(part.upper() if part in ("ac", "dc", "pv", "usb", "bms", "soc")
                    else part.capitalize()
                    for part in str(sensor_id).replace("-", "_").split("_") if part)


def _infer_sensor_meta(sensor_id: str):
    lc = str(sensor_id).lower()
    name = _humanize_sensor_id(sensor_id)
    unit = None
    device_class = None
    state_class = None
    if "voltage" in lc or lc.endswith("_v"):
        unit, device_class, state_class = "V", "voltage", "measurement"
    elif "current" in lc:
        unit, device_class, state_class = "A", "current", "measurement"
    elif "power" in lc or lc.endswith("_w"):
        unit, device_class, state_class = "W", "power", "measurement"
    elif "frequency" in lc or "freq" in lc:
        unit, device_class, state_class = "Hz", "frequency", "measurement"
    elif "temp" in lc:
        unit, device_class, state_class = "°C", "temperature", "measurement"
    elif lc.endswith("_wh") or "_wh_" in lc:
        unit, device_class = "Wh", "energy"
        # Remaining Wh is a point-in-time capacity, not an energy meter.
        state_class = None if "remaining" in lc else "total_increasing"
    elif "soc" in lc or "percentage" in lc:
        unit, device_class, state_class = "%", "battery", "measurement"
    elif lc == "remaining_time_minutes":
        unit, device_class, state_class = None, None, None
    elif "remaining_time" in lc or lc.endswith("_time"):
        unit, device_class, state_class = "min", "duration", "measurement"
    elif "cycle" in lc or "count" in lc:
        state_class = "total_increasing"
    return name, unit, device_class, state_class




_PUBLISHED_SENSOR_CONFIGS = set()

_NON_SENSOR_EXACT = {
    "ac_data", "battery_data", "dc_data", "grid_data", "pv_data", "pack_data",
    "hmi_data", "temp_data", "bms_data", "bms_celldata", "measure_data",
    "work_profile", "device_key", "device_dk", "device_type", "mac_set",
    "output_power_set", "power_retention_set", "smart_socket_mode",
    "timed_charge_connection", "timed_grid_connection",
    "load_power_consumption", "solar_panel_power_generation", "power_generation",
    "device_status_raw", "fault_code_raw", "signal_strength", "signalStrength",
    "signal_strength_set",
}

_TSL_DUPLICATE_PREFERRED_KEYS = {
    "soc": "battery_percentage",
    "remaining_time": "remaining_time_minutes",
    "pv_total_power": "pv_input_power",
    "pv_1_power": "pv_input_power",
    "pv_1_voltage": "pv_panel_voltage",
    "grid_frequency": "grid_freq",
    "ac_power": "ac_output_power",
    "dc_total_power": "dc_output_power",
    "battery_total_voltage": "battery_voltage",
    "BatCycleCnt": "battery_cycles",
    "AllowMaxChgCurr": "bms_allow_max_charge_current",
    "MosStatus": "bms_mos_status",
    "bms_mos_temp": "temp_bms",
    "inv_temp_max": "temp_inv",
    "mppt_temp_max": "temp_mppt",
}
_TSL_DUPLICATE_PREFERRED_KEYS.update({
    "ac_data_ac_power": "ac_output_power",
    "ac_data_ac_voltage": "ac_output_voltage",
    "battery_data_soc": "battery_percentage",
    "battery_data_battery_total_power": "battery_total_power",
    "battery_data_battery_total_voltage": "battery_voltage",
    "battery_data_remaining_time": "remaining_time_minutes",
    "battery_data_battery_temp": "battery_temp",
    "dc_data_dc_total_power": "dc_output_power",
    "dc_data_dc_12v_power": "dc12v_power",
    "dc_data_dc_12v_voltage": "dc12v_voltage",
    "dc_data_dc_24v_power": "dc24v_power",
    "dc_data_dc_24v_voltage": "dc24v_voltage",
    "dc_data_typec_1_power": "typec_1_power",
    "dc_data_typec_1_voltage": "typec_1_voltage",
    "dc_data_typec_2_power": "typec_2_power",
    "dc_data_typec_2_voltage": "typec_2_voltage",
    "dc_data_usb_1_power": "usb_a1_power",
    "dc_data_usb_1_voltage": "usb_a1_voltage",
    "dc_data_usb_2_power": "usb_a2_power",
    "dc_data_usb_2_voltage": "usb_a2_voltage",
    "dc_data_usb_3_power": "usb_a3_power",
    "dc_data_usb_3_voltage": "usb_a3_voltage",
    "dc_data_usb_4_power": "usb_a4_power",
    "dc_data_usb_4_voltage": "usb_a4_voltage",
    "dc_12V_power": "dc12v_power",
    "dc_12V_voltage": "dc12v_voltage",
    "dc_24V_power": "dc24v_power",
    "dc_24V_voltage": "dc24v_voltage",
    "usb_1_power": "usb_a1_power",
    "usb_1_voltage": "usb_a1_voltage",
    "usb_2_power": "usb_a2_power",
    "usb_2_voltage": "usb_a2_voltage",
    "usb_3_power": "usb_a3_power",
    "usb_3_voltage": "usb_a3_voltage",
    "usb_4_power": "usb_a4_power",
    "usb_4_voltage": "usb_a4_voltage",
    "grid_data_grid_b_power": "grid_b_power",
    "grid_data_grid_frequency": "grid_freq",
    "grid_data_grid_voltage": "grid_voltage",
    "pv_data_pv_total_power": "pv_input_power",
    "pv_data_pv_1_power": "pv_input_power",
    "pv_data_pv_1_voltage": "pv_panel_voltage",
})
for _cell in range(1, 15):
    _TSL_DUPLICATE_PREFERRED_KEYS[f"CellVoltage{_cell}"] = f"battery_cell_{_cell:02d}_voltage"
    _TSL_DUPLICATE_PREFERRED_KEYS[f"bms_celldata_no_cellvoltage{_cell}"] = f"battery_cell_{_cell:02d}_voltage"

_INFER_NAME_KEYS = {
    "hmi_field1_raw", "hmi_field2_uptime_candidate",
    "ac_input_power", "ac_output_power", "ac_output_voltage",
    "battery_current", "battery_cycles", "battery_percentage",
    "battery_remaining_wh", "battery_total_power", "battery_voltage",
    "bms_allow_max_charge_current", "bms_mos_status",
    "dc_output_power", "dc12v_current", "dc12v_power", "dc12v_voltage",
    "dc24v_current", "dc24v_power", "dc24v_voltage",
    "device_status", "device_status_raw", "fault_code", "fault_code_raw",
    "grid_b_power", "grid_freq", "grid_voltage",
    "pv_input_power", "pv_panel_voltage", "remaining_time_minutes",
    "temp_bms", "temp_inv", "temp_mppt",
    "total_input_power", "total_output_power", "uptime_minutes_lan",
    "typec_1_current", "typec_1_power", "typec_1_voltage",
    "typec_2_current", "typec_2_power", "typec_2_voltage",
    "usb_a1_current", "usb_a1_power", "usb_a1_voltage",
    "usb_a2_current", "usb_a2_power", "usb_a2_voltage",
    "usb_a3_current", "usb_a3_power", "usb_a3_voltage",
    "usb_a4_current", "usb_a4_power", "usb_a4_voltage",
}
for _cell in range(1, 15):
    _INFER_NAME_KEYS.add(f"battery_cell_{_cell:02d}_voltage")


def _is_publishable_sensor(sensor_id, cache, args=None):
    key = str(sensor_id)
    if not key or key.startswith("_"):
        return False
    if key in _NON_SENSOR_EXACT or key.endswith("_data"):
        return False
    if key in SWITCH_HEX:
        return False
    if args is not None:
        if key in (getattr(args, "_tsl_select_catalog", {}) or {}):
            return False
        if key in (getattr(args, "_tsl_number_catalog", {}) or {}):
            return False
    try:
        info = _load_tsl_controls().get(key) or {}
        if info.get("writable"):
            return False
    except Exception:
        pass
    preferred = _TSL_DUPLICATE_PREFERRED_KEYS.get(key)
    if preferred and preferred in cache:
        return False
    try:
        if key == "battery_total_voltage" and 0 < float(cache.get(key) or 0) < 10:
            return False
    except (TypeError, ValueError):
        pass
    return True


def apply_tsl_preferred_aliases(decoded):
    changed = set()

    def _num(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _valid(preferred, value):
        n = _num(value)
        if n is None:
            return True
        if preferred == "battery_voltage":
            return 40.0 <= n <= 70.0
        if preferred == "battery_percentage":
            return 0.0 <= n <= 100.0
        if preferred == "remaining_time_minutes":
            return 0.0 <= n <= 1440.0
        if preferred == "grid_voltage":
            return 0.0 <= n <= 300.0
        if preferred == "pv_panel_voltage":
            return 0.0 <= n <= 1000.0
        if preferred.endswith("_voltage"):
            return 0.0 <= n <= 300.0
        if preferred.endswith("_power") or preferred in ("ac_input_power", "ac_output_power", "grid_b_power"):
            return -10000.0 <= n <= 10000.0
        return True

    for source, preferred in _TSL_DUPLICATE_PREFERRED_KEYS.items():
        if source not in decoded or preferred in decoded:
            continue
        value = decoded[source]
        if not _valid(preferred, value):
            continue
        decoded[preferred] = value
        changed.add(preferred)
    return changed


def apply_dc_sensor_zero_baseline(cache, decoded):
    if decoded.get("dc_switch") is True or cache.get("dc_switch") is True:
        return set()
    if any(k in decoded for k in DC_OUTPUT_SENSOR_KEYS):
        return set()
    changed = set()
    for key in DC_OUTPUT_SENSOR_KEYS:
        if key not in cache:
            decoded[key] = 0
            changed.add(key)
    return changed


def apply_cell_voltage_total_fallback(cache, decoded):
    if "battery_voltage" in decoded:
        return set()
    values = []
    for cell in range(1, 14):
        key = f"battery_cell_{cell:02d}_voltage"
        value = decoded.get(key, cache.get(key))
        try:
            value = float(value)
        except (TypeError, ValueError):
            return set()
        if value > 10:
            value = value / 1000.0
        if not 2.5 <= value <= 4.5:
            return set()
        values.append(value)
    total = round(sum(values), 1)
    if not 40.0 <= total <= 70.0:
        return set()
    decoded["battery_voltage"] = total
    return {"battery_voltage"}


def publish_sensor_discovery_config(mqtt, base_topic, sensor_id):
    if sensor_id in _PUBLISHED_SENSOR_CONFIGS:
        return
    device_key = base_topic.rstrip("/").split("/")[-1] or DEVICE_KEY
    device = {
        "identifiers": [device_key],
        "name": DEVICE_NAME,
        "manufacturer": "Landbook",
        "model": os.environ.get("PRODUCT_KEY") or "TSL LAN device",
        "serial_number": device_key,
    }
    if (sensor_id in SENSOR_DEFS
            and sensor_id not in _TSL_DUPLICATE_PREFERRED_KEYS
            and sensor_id not in _INFER_NAME_KEYS):
        name, unit, device_class, state_class = SENSOR_DEFS[sensor_id]
    else:
        name, unit, device_class, state_class = _infer_sensor_meta(sensor_id)
    config = {
        "name": name,
        "object_id": f"{DEVICE_OBJECT_ID}_{sensor_id}",
        "has_entity_name": True,
        "state_topic": f"{base_topic}/sensors/{sensor_id}",
        "unique_id": f"{device_key}_{sensor_id}",
        "device": device,
        "availability_topic": f"{base_topic}/availability",
    }
    cat = _entity_category(sensor_id)
    if cat:
        config["entity_category"] = cat
    if unit:
        config["unit_of_measurement"] = unit
    if device_class:
        config["device_class"] = device_class
    if state_class:
        config["state_class"] = state_class
    if sensor_id in SENSOR_DISPLAY_PRECISION:
        config["suggested_display_precision"] = SENSOR_DISPLAY_PRECISION[sensor_id]
    if sensor_id in EXPIRING_SENSOR_IDS:
        config["force_update"] = True
    mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", json.dumps(config), retain=True)
    _PUBLISHED_SENSOR_CONFIGS.add(sensor_id)


def publish_sensor_cache(mqtt, base_topic, cache, keys=None, args=None):
    sensor_ids = list(cache.keys()) if keys is None else list(keys)
    for key in sensor_ids:
        if key in cache and _is_publishable_sensor(key, cache, args):
            publish_sensor_discovery_config(mqtt, base_topic, key)
            mqtt.publish(f"{base_topic}/sensors/{key}", str(_sensor_value(key, cache[key])), retain=False)


def clear_retained_sensor_states(mqtt, base_topic):
    for key in SENSOR_DEFS:
        mqtt.publish(f"{base_topic}/sensors/{key}", b"", retain=True)


# ══════════════════════════════════════════════════════════════════════════════
# Derived sensors & state tracking
# ══════════════════════════════════════════════════════════════════════════════

def calculate_total_output_power(values):
    grid_out = max(float(values.get("grid_b_power") or 0), 0.0)
    ac_out = max(float(values.get("ac_output_power") or 0), 0.0)
    if "dc_output_power" in values:
        dc_out = float(values.get("dc_output_power") or 0)
    else:
        dc_out = _dc_component_power(values)
        if dc_out is None:
            dc_out = 0.0
    ac_grid_total = max(grid_out, ac_out) if abs(grid_out - ac_out) <= 1 else grid_out + ac_out
    return round(ac_grid_total + dc_out, 2)


def apply_derived_sensors(cache):
    if any(k in cache for k in ("pv_input_power", "ac_input_power")):
        cache["total_input_power"] = round(
            float(cache.get("pv_input_power") or 0) + float(cache.get("ac_input_power") or 0), 2
        )
    if any(k in cache for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
        cache["total_output_power"] = calculate_total_output_power(cache)


def apply_battery_capacity_sensors(cache, decoded, args):
    if "battery_percentage" not in decoded:
        return set()
    capacity = float(getattr(args, "battery_capacity_wh", 0) or 0)
    if capacity <= 0:
        return set()
    soc = float(decoded["battery_percentage"])
    if not 0 <= soc <= 100:
        return set()
    cache["battery_remaining_wh"] = int(round(capacity * soc / 100.0))
    return {"battery_remaining_wh"}


def apply_battery_power_balance(cache, decoded, args):
    if "battery_total_power" in decoded:
        cache["_battery_total_power_source"] = "device"
        cache.pop("_battery_total_power_estimated", None)
        return set()
    if "battery_total_power" in cache and cache.get("_battery_total_power_source") != "estimated":
        return set()
    if not any(k in decoded for k in ("pv_input_power", "ac_input_power", "grid_b_power",
                                       "ac_output_power", "dc_output_power")):
        return set()
    if "total_input_power" not in cache or "total_output_power" not in cache:
        return set()
    power = round(float(cache.get("total_input_power") or 0) - float(cache.get("total_output_power") or 0), 2)
    cache["battery_total_power"] = int(power) if float(power).is_integer() else power
    cache["_battery_total_power_source"] = "estimated"
    cache["_battery_total_power_estimated"] = True
    changed = {"battery_total_power"}
    voltage = cache.get("battery_voltage")
    try:
        voltage = float(voltage)
    except (TypeError, ValueError):
        voltage = 0
    if voltage <= 0:
        voltage = float(getattr(args, "battery_current_fallback_voltage", 0) or 0)
    if voltage > 0:
        cache["battery_current"] = round(power / voltage, 2)
        changed.add("battery_current")
    return changed



def normalize_remaining_time_from_frame(decoded, cache):
    """Normalizza il tempo residuo usando solo il valore TSL reale.

    Sorgente accettata: battery_data.remaining_time, che il walker espone come
    `remaining_time` e poi come `remaining_time_minutes`.

    `pack_data` non viene usato: è per pacchi/moduli batteria aggiuntivi.
    Valori enormi tipo 8177/42752/43008 vengono eliminati e HA mantiene
    l'ultimo valore valido.
    """
    if ("remaining_time_minutes" not in decoded
            and "remaining_time" not in decoded
            and "battery_data_remaining_time" not in decoded
            and "battery_data" not in decoded):
        return set()

    def _to_int(value):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    raw_minutes = _to_int(decoded.get("remaining_time_minutes"))
    tsl_minutes = _to_int(decoded.get("remaining_time"))
    battery_data_path_minutes = _to_int(decoded.get("battery_data_remaining_time"))
    battery_data_minutes = _to_int(decoded.get("battery_data"))

    # Sorgente primaria: TSL battery_data.remaining_time.
    # Il TSL ufficiale ha max=65535 Minutes e l'app può mostrare anche più giorni
    # in Standby. Quindi NON tagliare a 24h: accetta il valore TSL reale.
    # Scarta solo sentinelle/valori palesemente sporchi osservati nei frame corrotti.
    invalid_remaining_values = {42752, 43008, 65535}
    for minutes in (battery_data_path_minutes, tsl_minutes, battery_data_minutes, raw_minutes):
        if minutes is not None and 0 < minutes <= 65534 and minutes not in invalid_remaining_values:
            decoded["remaining_time_minutes"] = minutes
            cache["_last_valid_remaining_time_minutes"] = minutes
            return {"remaining_time_minutes"}

    # Valore assente o assurdo: non pubblicare il tempo sbagliato.
    # Se esiste un ultimo valore valido nella sessione, ripubblica quello per evitare Unknown.
    last = _to_int(cache.get("_last_valid_remaining_time_minutes") or cache.get("remaining_time_minutes"))
    if last is not None and 0 < last <= 65534 and last not in invalid_remaining_values:
        decoded["remaining_time_minutes"] = last
        return {"remaining_time_minutes"}

    decoded.pop("remaining_time_minutes", None)
    return set()


def guard_zero_remaining_time(decoded, cache):
    """Evita di pubblicare 0h quando la LAN/app manda remaining_time_minutes=0
    durante micro-carichi o PV leggero. In quel caso Home Assistant deve mantenere
    l'ultimo valore valido invece di fare 37h -> 0h -> 37h.
    """
    if "remaining_time_minutes" not in decoded:
        return
    try:
        minutes = int(float(decoded.get("remaining_time_minutes") or 0))
    except (TypeError, ValueError):
        return
    if minutes != 0:
        cache["_last_valid_remaining_time_minutes"] = minutes
        return

    def _num(key):
        try:
            return float(decoded.get(key) if key in decoded else cache.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    power = _num("battery_total_power")
    pv = _num("pv_input_power")
    outp = max(_num("grid_b_power"), _num("ac_output_power"), _num("dc_output_power"), _num("total_output_power"))
    inp = max(pv, _num("ac_input_power"), _num("total_input_power"))

    # Alcuni modelli con PV leggero / carico minimo inviano spesso 0 minuti anche se
    # la batteria è al 50%: non è un tempo reale, è "non calcolabile".
    if abs(power) < 30.0 and outp < 30.0 and inp < 30.0:
        decoded.pop("remaining_time_minutes", None)
        return

    # Se invece c'è potenza reale ma la LAN manda 0, lascia che il fallback stimato
    # ricalcoli il tempo dopo l'update del cache.

def apply_device_status_correction(cache, decoded):
    """Deriva lo stato operativo reale per carica/scarica.

    Su questa powerstation il codice firmware `device_status_raw` può restare a
    1/"In carica" anche mentre il Micro-Inverter sta erogando 100 W e la
    batteria sta realmente scaricando. Per Home Assistant quindi pubblichiamo
    lo stato dalla fisica dei flussi:

      - battery_total_power < 0  -> In scarica
      - battery_total_power > 0 con uscita attiva -> Carica e scarica
      - battery_total_power > 0 senza uscita -> In carica
      - potenze quasi zero -> Standby

    Il valore raw resta disponibile come `device_status_raw`; non viene più
    usato per sovrascrivere lo stato quando le potenze dicono il contrario.
    """
    if not any(k in decoded for k in (
        "device_status_raw", "battery_total_power", "grid_b_power",
        "ac_output_power", "dc_output_power", "pv_input_power", "ac_input_power",
    )):
        return set()

    def _num(key):
        try:
            val = decoded.get(key) if key in decoded else cache.get(key)
            return float(val or 0)
        except (TypeError, ValueError):
            return 0.0

    def _raw_status():
        try:
            return int(float(decoded.get("device_status_raw", cache.get("device_status_raw") or 0)))
        except (TypeError, ValueError):
            return None

    status_raw = _raw_status()
    if status_raw == 4:
        new_label = "Bypass"
    else:
        battery_power = _num("battery_total_power")
        output_power = max(_num("grid_b_power"), _num("ac_output_power"), _num("dc_output_power"))
        input_power = max(_num("pv_input_power"), _num("ac_input_power"))

        deadband_w = 30.0
        active_w = 30.0

        if battery_power <= -deadband_w:
            # Batteria negativa = sta alimentando i carichi/uscita.
            new_label = "In scarica"
        elif battery_power >= deadband_w:
            # Batteria positiva = sta caricando. Se c'è anche uscita attiva,
            # è il caso ibrido carica + scarica/carico.
            new_label = "Carica e scarica" if output_power > active_w else "In carica"
        elif input_power > active_w and output_power > active_w:
            new_label = "Carica e scarica" if input_power + deadband_w >= output_power else "In scarica"
        elif input_power > active_w:
            new_label = "In carica"
        elif output_power > active_w:
            new_label = "In scarica"
        elif abs(battery_power) < deadband_w and input_power < active_w and output_power < active_w:
            new_label = "Standby"
        elif status_raw is not None:
            new_label = DEVICE_STATUS_LABELS.get(status_raw, f"Stato {status_raw}")
        else:
            return set()

    if cache.get("device_status") != new_label:
        cache["device_status"] = new_label
        return {"device_status"}
    return set()


def apply_raw_status_labels(cache, decoded):
    changed = set()

    def unknownish(value):
        if value is None:
            return True
        text = str(value).strip().lower()
        return text in ("", "unknown", "sconosciuto", "none", "null")

    if "device_status_raw" in decoded and unknownish(decoded.get("device_status")):
        try:
            raw = int(float(decoded["device_status_raw"]))
            label = DEVICE_STATUS_LABELS.get(raw, f"Stato {raw}")
            if cache.get("device_status") != label:
                cache["device_status"] = label
                changed.add("device_status")
        except (TypeError, ValueError):
            pass
    if "fault_code_raw" in decoded and unknownish(decoded.get("fault_code")):
        try:
            raw = int(float(decoded["fault_code_raw"]))
            label = FAULT_CODE_LABELS.get(raw, f"Errore E{raw}")
            if cache.get("fault_code") != label:
                cache["fault_code"] = label
                changed.add("fault_code")
        except (TypeError, ValueError):
            pass
    return changed


# ══════════════════════════════════════════════════════════════════════════════
# Command handling
# ══════════════════════════════════════════════════════════════════════════════

def _normalize_output_power(value, args):
    watts = int(float(value))
    step = int(getattr(args, "output_power_step", 10) or 10)
    lo = int(getattr(args, "output_power_min", 100) or 100)
    hi = int(getattr(args, "output_power_max", 800) or 800)
    return max(lo, min(hi, (watts // step) * step))


def _command_tx_allowed(args, command_id, value, *, duplicate_window=None, opposite_window=None):
    """Throttle HA command bounces before they reach the device Wi-Fi module."""
    if args is None:
        return True
    now = time.time()
    duplicate_window = (
        float(duplicate_window)
        if duplicate_window is not None
        else float(getattr(args, "command_duplicate_window", COMMAND_DUPLICATE_WINDOW) or 0)
    )
    opposite_window = (
        float(opposite_window)
        if opposite_window is not None
        else float(getattr(args, "command_opposite_window", COMMAND_OPPOSITE_WINDOW) or 0)
    )
    history = getattr(args, "_last_command_tx", None)
    if not isinstance(history, dict):
        history = {}
    value = str(value)
    last = history.get(command_id)
    if last:
        last_value = str(last.get("value", ""))
        last_ts = float(last.get("ts", 0) or 0)
        age = now - last_ts
        if last_value == value and duplicate_window > 0 and age < duplicate_window:
            print(f"ignored duplicate {command_id} command: {value}", flush=True)
            return False
        if last_value != value and opposite_window > 0 and age < opposite_window:
            print(f"ignored rapid opposite {command_id} command: {last_value} -> {value}", flush=True)
            return False
    history[command_id] = {"value": value, "ts": now}
    args._last_command_tx = history
    return True


def handle_mqtt_command(topic, payload, device_sock, mqtt, base_topic, key, iv, args):
    prefix = f"{base_topic}/set/"
    if not topic.startswith(prefix):
        return
    command_id = topic[len(prefix):]
    payload = payload.strip()
    if not payload:
        return

    number_catalog = getattr(args, "_tsl_number_catalog", {}) or {}
    if command_id == "output_power" and "output_power_set" in number_catalog:
        command_id = "output_power_set"

    if command_id == INTELLIGENT_CHARGING_POWER_ID:
        try:
            watts = INTELLIGENT_CHARGING_WATTS[_intelligent_charge_index_from_watts(payload)]
        except ValueError:
            return
        if not _command_tx_allowed(args, command_id, str(watts), opposite_window=0.0):
            return
        frame = encode_cmd(
            0x0013,
            _next_packet_id(args),
            aes_encrypt(_build_intelligent_charging_payload(watts), key, iv),
        )
        _send_frame(device_sock, args, frame)
        _set_pending_command_state(args, command_id, str(watts), seconds=120)
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", str(watts), retain=True)
        print(f"sent intelligent charging power {watts}W", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60
        return

    if command_id in SWITCH_HEX:
        state = payload.upper()
        if state not in ("ON", "OFF"):
            return
        opposite_window = GRID_OPPOSITE_WINDOW if command_id == _grid_command_id() else None
        if not _command_tx_allowed(args, command_id, state, opposite_window=opposite_window):
            return
        switch = SWITCH_HEX[command_id]
        frame = _build_tsl_info_frame(switch, switch[state.lower()], key, iv, args, default_type=switch.get("type"))
        _send_frame(device_sock, args, frame)
        _set_pending_command_state(args, command_id, state)
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", state, retain=True)
        _dprint(f"sent {command_id} {state}", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60   # 60s grace dopo switch
        return

    # Dynamic select handler: any TSL ENUM control we exposed as a HA select
    # entity. The HA payload is the cloud label; we look up the int value via
    # the cached select catalog and send it as an ENUM TTLV.
    select_catalog = getattr(args, "_tsl_select_catalog", {}) or {}
    if command_id in select_catalog:
        info = select_catalog[command_id]
        options = info.get("options") or {}
        label_to_value = {str(v): int(k) for k, v in options.items()}
        if payload not in label_to_value:
            _dprint(f"select {command_id}: unknown label '{payload}', expected {list(label_to_value)}")
            return
        if not _command_tx_allowed(args, command_id, payload):
            return
        frame = _build_tsl_info_frame(info, label_to_value[payload], key, iv, args, default_type="ENUM")
        _send_frame(device_sock, args, frame)
        _set_pending_command_state(args, command_id, payload)
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", payload, retain=True)
        _dprint(f"sent {command_id}={payload} (value={label_to_value[payload]})", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60
        return

    if command_id in number_catalog:
        info = number_catalog[command_id]
        try:
            value = float(payload)
        except ValueError:
            return
        step = float(info.get("step") or 1)
        lo = info.get("min")
        hi = info.get("max")
        if lo is not None:
            value = max(float(lo), value)
        if hi is not None:
            value = min(float(hi), value)
        if step > 0:
            value = round(value / step) * step
        if float(value).is_integer():
            value = int(value)
        if not _command_tx_allowed(args, command_id, str(value), opposite_window=0.0):
            return
        frame = _build_tsl_info_frame(info, value, key, iv, args, default_type=info.get("type") or "INT")
        _send_frame(device_sock, args, frame)
        _set_pending_command_state(args, command_id, str(value), seconds=120)
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", str(value), retain=True)
        _dprint(f"sent {command_id}={value}", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60
        return

    if command_id == "output_power":
        try:
            watts = _normalize_output_power(payload, args)
        except ValueError:
            return
        if not _command_tx_allowed(
            args,
            "output_power",
            str(watts),
            duplicate_window=float(getattr(args, "output_power_debounce", 0.25) or 0.25),
            opposite_window=0.0,
        ):
            return
        args._pending_output_power = watts
        args._pending_output_power_due = time.time() + float(getattr(args, "output_power_debounce", 0.25) or 0.25)
        _set_pending_command_state(args, "output_power", str(watts), seconds=120)
        args._next_bus_kick = time.time() + 2.5
        _dprint(f"queued output_power {watts}W", flush=True)


def _flush_pending_output_power(device_sock, mqtt, base_topic, key, iv, args):
    watts = getattr(args, "_pending_output_power", None)
    due = getattr(args, "_pending_output_power_due", 0)
    if watts is None or time.time() < due:
        return
    try:
        output_info = _tsl_control_info("output_power_set", default_type="INT")
        frame = _build_tsl_info_frame(output_info, watts, key, iv, args, default_type="INT")
    except Exception as exc:
        print(f"output_power_set TSL command unavailable: {exc}", flush=True)
        args._pending_output_power = None
        args._pending_output_power_due = 0
        return
    _send_frame(device_sock, args, frame)
    print(f"sent output_power {watts}W; waiting for LAN confirmation", flush=True)
    args._pending_output_power = None
    args._pending_output_power_due = 0
    # Il device può bloccare il reporting per 60-120s mentre applica il nuovo
    # limite di potenza (reset interno inverter). Impostiamo una grace period
    # così non riconnettimamo (e non triggeriamo automazioni HA) durante questo periodo.
    args._cmd_grace_until = time.time() + 120


# ══════════════════════════════════════════════════════════════════════════════
# LAN key refresh
# ══════════════════════════════════════════════════════════════════════════════

LAN_KEY_CACHE_PATH = "/data/landbook_lan_key.json"


def _persist_lan_key_cache() -> None:
    """Write the freshly-refreshed LAN key bundle to /data so the next addon restart
    skips the cloud login."""
    bundle = {
        "email":       os.environ.get("WF_EMAIL", ""),
        "platform":    os.environ.get("PLATFORM", "landbook"),
        "lan_key_hex": os.environ.get("LAN_KEY_HEX", ""),
        "device_key":  os.environ.get("DEVICE_KEY", ""),
        "product_key": os.environ.get("PRODUCT_KEY", ""),
        "saved_at":    int(time.time()),
    }
    if not bundle["lan_key_hex"] or not bundle["device_key"]:
        return
    try:
        os.makedirs(os.path.dirname(LAN_KEY_CACHE_PATH), exist_ok=True)
        with open(LAN_KEY_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(bundle, f)
    except OSError as exc:
        print(f"LAN key cache write failed: {exc}", flush=True)


def _invalidate_lan_key_cache() -> None:
    try:
        os.remove(LAN_KEY_CACHE_PATH)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"LAN key cache invalidate failed: {exc}", flush=True)


def _refresh_lan_key(args) -> bool:
    global _BUS_MASK_CACHE, _BUS_MASK_SOURCE, _TSL_CONTROLS_CACHE
    try:
        from wf_autodiscovery import setup as _setup
        _setup(force=True)
        _BUS_MASK_CACHE = None
        _BUS_MASK_SOURCE = ""
        _TSL_CONTROLS_CACHE = None
        new_hex = os.environ.get("LAN_KEY_HEX", "").strip()
        if new_hex:
            new_key = base64.b64encode(bytes.fromhex(new_hex)).decode("ascii")
            if new_key != args.key:
                args.key = new_key
                _persist_lan_key_cache()
                print("LAN key refreshed from cloud", flush=True)
                return True
        return False
    except Exception as exc:
        print(f"LAN key refresh failed: {exc}", flush=True)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# WiFi freeze recovery
# ══════════════════════════════════════════════════════════════════════════════


def stop_addon_after_freeze(mqtt, availability_topic, topic, streak, duration):
    """Ferma volontariamente l'add-on dopo freeze consecutivi.

    Esce dal processo principale: con run.sh che fa `exec python3`, il servizio
    dell'add-on termina invece di continuare a riconnettersi all'infinito.
    """
    print(
        f"Freeze consecutivi={streak}: pubblico offline e spengo add-on",
        flush=True,
    )
    try:
        publish_wifi_frozen_alert(
            mqtt,
            topic,
            reason="freeze_streak_shutdown",
            streak=streak,
            duration=duration,
        )
    except Exception as exc:
        print(f"MQTT wifi_frozen shutdown alert failed: {exc}", flush=True)
    try:
        mqtt.publish_resilient(availability_topic, "offline", retain=True)
    except Exception as exc:
        print(f"MQTT availability offline publish failed: {exc}", flush=True)
    try:
        mqtt.disconnect()
    except Exception:
        pass
    raise SystemExit(0)

# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════



# ---- restored low-level command helpers ----


def _decoded_reports_ac_off(decoded):
    if decoded.get("device_status_raw") == 0:
        return True
    if decoded.get("device_status") == "Standby":
        return True
    profile = decoded.get("work_profile")
    if isinstance(profile, str):
        parts = profile.split(",", 1)
        if parts and parts[0].strip() == "0":
            return True
    return False


def words16(data):
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2)]


def _initial_command_states_from_env() -> dict:
    raw = os.environ.get("WF_SWITCH_STATES", "").strip()
    if not raw:
        return {}
    states = {}
    valid = set(SWITCH_HEX)
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in valid and value:
            states[key] = value
    return states

# ---- end low-level command helpers ----

# ---- restored command-state helpers (0.6.25 startup fix) ----


def apply_grid_frequency_default(cache, decoded, args):
    if "grid_freq" in decoded:
        return set()
    default_freq = float(getattr(args, "grid_frequency_default", 0) or 0)
    if default_freq <= 0:
        return set()
    def _num(key):
        try:
            return float(decoded.get(key) if key in decoded else cache.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    has_grid_context = (
        _num("grid_voltage") > 30.0 or
        abs(_num("grid_b_power")) > 5.0 or
        _num("ac_input_power") > 5.0 or
        _num("ac_output_power") > 5.0
    )
    if not has_grid_context:
        return set()
    cache["grid_freq"] = int(default_freq) if float(default_freq).is_integer() else default_freq
    return {"grid_freq"}


def zero_sensor_values_for_frame(cache, decoded):
    if (decoded.get("grid_b_power") == 0 and decoded.get("ac_input_power") == 0
            and decoded.get("ac_output_power") == 0 and "grid_voltage" not in decoded):
        val = 0
        return {"grid_voltage": val} if cache.get("grid_voltage") != val else {}
    return {}


def suppress_transient_ac_zeros(cache, decoded, args):
    hold_seconds = float(getattr(args, "ac_zero_hold_seconds", 0) or 0)
    if hold_seconds <= 0:
        return set()
    if _decoded_reports_ac_off(decoded):
        cache.pop("_ac_zero_pending_since", None)
        return set()
    now = time.time()
    has_real = any(
        k in decoded and float(decoded.get(k) or 0) != 0
        for k in AC_TRANSIENT_ZERO_KEYS
    )
    if has_real:
        cache.pop("_ac_zero_pending_since", None)
        return set()
    suppress = {
        k for k in AC_TRANSIENT_ZERO_KEYS
        if k in decoded and float(decoded.get(k) or 0) == 0 and float(cache.get(k) or 0) != 0
    }
    if not suppress:
        cache.pop("_ac_zero_pending_since", None)
        return set()
    pending_since = cache.setdefault("_ac_zero_pending_since", now)
    if now - float(pending_since) >= hold_seconds:
        cache.pop("_ac_zero_pending_since", None)
        return set()
    for k in suppress:
        decoded.pop(k, None)
    if any(k in suppress for k in ("grid_b_power", "ac_output_power")):
        decoded.pop("total_output_power", None)
    if "ac_input_power" in suppress:
        decoded.pop("total_input_power", None)
    return suppress


def extract_reported_command_states(plain):
    ws = words16(plain)
    reported = {}
    _extract_output_power_set(plain, reported)
    if "output_power_set" in reported:
        reported["output_power"] = str(reported.pop("output_power_set"))
    if len(ws) == 1 and ws[0] in GRID_STATE_WORDS:
        reported["grid"] = GRID_STATE_WORDS[ws[0]]
    if len(ws) >= 1 and ws[0] in AC_STATE_WORDS:
        reported["ac"] = AC_STATE_WORDS[ws[0]]
    if len(ws) >= 2 and ws[1] in DC_STATE_WORDS:
        reported["dc"] = DC_STATE_WORDS[ws[1]]
    for switch_id, mapping in STATE_TAGS.items():
        for w in reversed(ws):
            if w in mapping:
                reported[switch_id] = mapping[w]
                break
    for switch_id, tag_map in VALUE_STATES.items():
        for i in range(len(ws) - 1, 0, -1):
            value_map = tag_map.get(ws[i - 1])
            if value_map and ws[i] in value_map:
                reported[switch_id] = value_map[ws[i]]
                break
    for i in range(len(ws) - 1):
        if ws[i] == 0x00DA and ws[i + 1] in MODE_LABEL_BY_VAL:
            reported["mode"] = MODE_LABEL_BY_VAL[ws[i + 1]]
    return reported


def _set_pending_command_state(args, command_id, value, seconds=45):
    if args is None:
        return
    pending = getattr(args, "_pending_command_states", None)
    if not isinstance(pending, dict):
        pending = {}
    pending[command_id] = {
        "value": str(value),
        "until": time.time() + float(seconds),
    }
    args._pending_command_states = pending


def _command_state_allowed(args, command_id, value):
    if args is None:
        return True
    pending = getattr(args, "_pending_command_states", None)
    if not isinstance(pending, dict):
        return True
    wait = pending.get(command_id)
    if not wait:
        return True
    expected = str(wait.get("value", ""))
    current = str(value)
    until = float(wait.get("until", 0) or 0)
    now = time.time()
    if current != expected and now <= until:
        _dprint(f"ignored stale {command_id}={current}; waiting for {expected}", flush=True)
        return False
    pending.pop(command_id, None)
    args._pending_command_states = pending
    return True



def _normalize_output_power_state_value(value):
    """Normalize output_power_set values for HA number state.

    The device can report the TSL raw value scaled x10 (e.g. 1000 for 100 W).
    Home Assistant number range is real watts 100..800, so never publish raw x10.
    """
    try:
        v = int(float(value))
    except (TypeError, ValueError):
        return None
    if 100 <= v <= 800:
        return v
    if 1000 <= v <= 8000 and v % 10 == 0:
        return v // 10
    return None

def publish_reported_command_states(mqtt, base_topic, reported, args=None):
    valid = set(SWITCH_HEX)
    if args is not None:
        valid.update((getattr(args, "_tsl_select_catalog", {}) or {}).keys())
        valid.update((getattr(args, "_tsl_number_catalog", {}) or {}).keys())
    for command_id, value in reported.items():
        command_id = _canonical_command_id(command_id)
        if command_id not in valid:
            continue
        if command_id in LEGACY_COMMAND_STATE_CLEANUP:
            continue
        if command_id == "output_power_set":
            value = _normalize_output_power_state_value(value)
            if value is None:
                continue
        if not _command_state_allowed(args, command_id, value):
            continue
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", str(value), retain=True)


def publish_output_power_state(mqtt, base_topic, watts, source="LAN", args=None):
    watts = _normalize_output_power_state_value(watts)
    if watts is None:
        return
    command_id = "output_power_set"
    if args is not None and command_id not in (getattr(args, "_tsl_number_catalog", {}) or {}):
        return
    if not _command_state_allowed(args, command_id, str(watts)):
        return
    mqtt.publish(f"{base_topic}/cmd_state/{command_id}", str(watts), retain=True)
    _dprint(f"{source} output_power_set={watts}W", flush=True)


def publish_initial_command_states(mqtt, base_topic, args=None):
    initial = _initial_command_states_from_env()
    for command_id in LEGACY_COMMAND_STATE_CLEANUP:
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", b"", retain=True)
    for switch_id in SWITCH_HEX:
        mqtt.publish(f"{base_topic}/cmd_state/{switch_id}", initial.get(switch_id, b""), retain=True)
    if args is not None:
        for select_id, info in ((getattr(args, "_tsl_select_catalog", {}) or {}).items()):
            current_label = info.get("current_label")
            if current_label not in (None, ""):
                mqtt.publish(f"{base_topic}/cmd_state/{select_id}", str(current_label), retain=True)
        for number_id, info in ((getattr(args, "_tsl_number_catalog", {}) or {}).items()):
            current_value = info.get("current_value")
            if current_value not in (None, ""):
                if number_id == "output_power_set":
                    current_value = _normalize_output_power_state_value(current_value)
                    if current_value is None:
                        continue
                mqtt.publish(f"{base_topic}/cmd_state/{number_id}", str(current_value), retain=True)


def publish_inferred_command_states(mqtt, base_topic, cache, decoded, args=None):
    inferred = {}
    grid_id = _grid_command_id()
    dc_id = _dc_command_id()

    def _num(key):
        try:
            return float(decoded.get(key) if key in decoded else cache.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    # Segue le modifiche fatte dall'app usando solo prove fisiche dai sensori LAN.
    # Evita la vecchia scansione generica dei frame, che poteva creare switch falsi.
    grid_output_power = max(_num("grid_b_power"), _num("ac_output_power"))
    if grid_id and grid_output_power >= 5:
        if args is not None:
            args._grid_zero_reads = 0
        inferred[grid_id] = "ON"
    elif grid_id and "grid_power_switch_set" in decoded:
        if bool(decoded.get("grid_power_switch_set")):
            if args is not None:
                args._grid_zero_reads = 0
            inferred[grid_id] = "ON"
        else:
            inferred[grid_id] = "OFF"
    elif grid_id and cache.get("grid_power_switch_set") is False:
        inferred[grid_id] = "OFF"
    elif grid_id and cache.get("grid_power_switch_set") is True:
        inferred[grid_id] = "ON"
    elif grid_id and any(k in decoded for k in ("grid_b_power", "ac_output_power", "ac_input_power")):
        # During Output Priority / grid startup the LAN stream can briefly
        # report 0 W even though the command bit and the output settle to ON a
        # moment later. Do not turn the HA switch off on a single zero sample.
        if args is None:
            inferred[grid_id] = "OFF"
        else:
            zero_reads = int(getattr(args, "_grid_zero_reads", 0) or 0) + 1
            args._grid_zero_reads = zero_reads
            if zero_reads >= 3:
                inferred[grid_id] = "OFF"

    dc_power = max(
        _num("dc_output_power"),
        _num("dc12v_power"),
        _num("dc24v_power"),
        _num("typec_1_power"),
        _num("typec_2_power"),
        _num("usb_a1_power"),
        _num("usb_a2_power"),
        _num("usb_a3_power"),
        _num("usb_a4_power"),
    )
    if dc_id and decoded.get("dc_switch") is False:
        inferred[dc_id] = "OFF"
    elif dc_id and decoded.get("dc_switch") is True:
        # Some LAN frames mark dc_switch=True when only the auxiliary/LED rail
        # is awake (for example USB voltage present with 0-1 W). Do not flip
        # the HA switch on unless there is real DC output or the user cache
        # already says the switch is on.
        if dc_power >= 3 or cache.get("dc_switch") is True:
            inferred[dc_id] = "ON"
        elif cache.get("dc_switch") is False:
            inferred[dc_id] = "OFF"
    elif dc_id and cache.get("dc_switch") is False:
        inferred[dc_id] = "OFF"
    elif dc_id and cache.get("dc_switch") is True:
        inferred[dc_id] = "ON"
    elif dc_id and dc_power >= 3:
        inferred[dc_id] = "ON"
    elif dc_id and any(k in decoded for k in (
        "usb_a1_voltage",
        "usb_a2_voltage",
        "usb_a3_voltage",
        "usb_a4_voltage",
        "dc12v_voltage",
        "dc24v_voltage",
    )):
        dc_voltage = max(
            _num("usb_a1_voltage"),
            _num("usb_a2_voltage"),
            _num("usb_a3_voltage"),
            _num("usb_a4_voltage"),
            _num("dc12v_voltage"),
            _num("dc24v_voltage"),
        )
        if dc_voltage <= 1:
            inferred[dc_id] = "OFF"

    if inferred:
        publish_reported_command_states(mqtt, base_topic, inferred, args)
        _dprint(f"inferred command states from sensors: {inferred}", flush=True)
    return inferred


def apply_reported_sensor_overrides(cache, reported):
    changed = set()

    def set_zero(key):
        if cache.get(key) != 0:
            changed.add(key)
        cache[key] = 0

    grid_id = _grid_command_id() or "grid"
    dc_id = _dc_command_id() or "dc"
    if reported.get(grid_id) == "OFF" or reported.get("grid") == "OFF":
        for key in ("grid_b_power",):
            set_zero(key)
    if reported.get(dc_id) == "OFF" or reported.get("dc") == "OFF":
        for key in DC_OUTPUT_SENSOR_KEYS:
            set_zero(key)
    if changed:
        apply_derived_sensors(cache)
        changed.update(("total_input_power", "total_output_power"))
    return changed


def apply_explicit_switch_sensor_overrides(decoded, cache=None):
    changed = set()
    cache = cache or {}

    def set_zero(key):
        if decoded.get(key) != 0:
            changed.add(key)
        decoded[key] = 0

    # The TSL switch state is authoritative. Some frames keep reporting a tiny
    # phantom dc_output_power (observed 4 W) while the app and TSL say DC is off.
    dc_is_off = decoded.get("dc_switch") is False or (
        "dc_switch" not in decoded and cache.get("dc_switch") is False
    )
    if dc_is_off:
        for key in DC_OUTPUT_SENSOR_KEYS:
            set_zero(key)
    return changed

# ---- end restored helpers ----

def run(args):
    availability_topic = f"{args.topic}/availability"
    device_key = _device_key(args)
    mqtt = MqttClient(
        args.mqtt_host, args.mqtt_port,
        args.mqtt_user, args.mqtt_password,
        client_id=f"landbook_lan_bridge_{device_key}",
        will_topic=availability_topic,
        will_payload="offline",
        will_retain=True,
    )
    mqtt.connect()
    # Connessione MQTT dedicata alle prese (Last Will separato dalla powerstation).
    args._socket_liveness = _start_socket_liveness(args)
    print("MQTT connected; publishing discovery...", flush=True)
    publish_discovery(mqtt, args.topic, args)
    subscribe_command_topics(mqtt, args.topic, args)

    publish_initial_command_states(mqtt, args.topic, args)
    clear_retained_sensor_states(mqtt, args.topic)
    cleanup_disabled_cache_files(args)

    sensor_cache: dict = {}
    next_smart_socket_poll = 0.0

    reconnect_delay = RECONNECT_DELAY_INIT
    unreachable_since: float | None = None
    broken_pipe_since: float | None = None
    lan_disconnected_since: float | None = None
    availability_offline_sent = False
    sensor_silence_streak = 0       # riconnessioni consecutive senza dati sensori
    sensor_silence_since: float | None = None
    session_had_sensor_data = False  # questa sessione TCP ha ricevuto almeno un dato
    last_wifi_frozen_alert = 0.0
    unreachable_alert_streak = 0    # alert LAN unreachable consecutivi
    first_alert_at_episode = None   # timestamp del primo alert pubblicato in questo episodio di freeze

    try:
        while True:
            sock = None
            try:
                print(f"Connecting {args.device_host}:{args.device_port}...", flush=True)
                args._lan_packet_id = 1   # reset prima del login (Bug 6 fix)
                sock, key, iv = connect_and_login(
                    args.device_host, args.device_port, args.key,
                    float(getattr(args, "timeout", 10) or 10),
                )
                # ── Connected ────────────────────────────────────────────────
                if lan_disconnected_since is not None:
                    print(f"LAN recovered after {time.time() - lan_disconnected_since:.0f}s", flush=True)
                unreachable_since = None
                unreachable_alert_streak = 0
                # broken_pipe_since NON viene resettato qui: il TCP connect può
                # riuscire e poi dare subito Broken pipe (firmware non pronto).
                # Viene resettato solo quando arrivano dati sensori reali.
                reconnect_delay = RECONNECT_DELAY_INIT
                lan_disconnected_since = None
                availability_offline_sent = False
                session_had_sensor_data = False
                # Reset stato pendente dalla sessione precedente (Bug 2 fix):
                # evita comandi indesiderati su device appena riconnesso
                args._pending_output_power  = None
                args._pending_output_power_due = 0
                args._next_bus_kick         = 0
                args._cmd_grace_until       = 0  # reset grace period su riconnessione
                mqtt.publish(availability_topic, "online", retain=True)
                print(f"LAN connected; MQTT at {args.mqtt_host}:{args.mqtt_port}", flush=True)

                args._lan_packet_id = 1
                time.sleep(1.0)  # grace period post-login prima dei comandi
                send_report_subscription(sock, key, iv, args)
                sent_mask_ids = resolve_bus_mask_ids(args)
                send_bus_mask(sock, key, iv, args, ids=sent_mask_ids)
                send_bus_refresh(sock, key, iv, args)          # sollecito reporting
                last_bus_refresh_sent = time.time()

                # ── Nudge LAN+WiFi High Frequency Reporting al login ───────────
                # Invio singolo (non ripetuto) per provare a far partire la sessione
                # in modalità alta frequenza, invece di aspettare che il device la
                # scelga da solo. Valore 3 = LAN + Wi-Fi (verificato empiricamente:
                # il valore 1 "solo LAN" è un no-op su questo firmware, non sveglia
                # il device — solo 3 lo stimola davvero). Non viene mai re-inviato
                # durante la sessione anche se il device torna in Low da solo (per
                # non rincorrerlo).
                try:
                    _hfr_catalog = getattr(args, "_tsl_select_catalog", {}) or {}
                    _hfr_info = _hfr_catalog.get("high_frequency_reporting")
                    if _hfr_info:
                        _hfr_frame = _build_tsl_info_frame(
                            _hfr_info, 3, key, iv, args, default_type="ENUM"
                        )
                        _send_frame(sock, args, _hfr_frame)
                        _dprint("sent high_frequency_reporting=3 (LAN+WiFi) one-shot al login", flush=True)
                    else:
                        _dprint("high_frequency_reporting non trovato nel select catalog: nudge saltato", flush=True)
                except Exception as _hfr_exc:
                    _dprint(f"high_frequency_reporting nudge fallito: {_hfr_exc}", flush=True)

                # ── Drain comandi MQTT stantii ────────────────────────────────
                # Il broker MQTT mantiene la connessione attiva durante i disconnect
                # LAN: i comandi inviati dall'utente in HA si accumulano nel buffer
                # rx e verrebbero eseguiti tutti in sequenza appena il device torna
                # online, causando comportamenti caotici (grid ON→OFF→ON→OFF).
                # Scartiamo per ~1s qualsiasi comando accodato durante il disconnect.
                _drain_end = time.time() + float(getattr(args, "mqtt_stale_drain_seconds", 2.0) or 2.0)
                _drained = 0
                while time.time() < _drain_end:
                    for _t, _p, _r in mqtt.read_messages():
                        if not _r:
                            _drained += 1
                            _dprint(f"discarded stale MQTT command: {_t}={_p}", flush=True)
                    time.sleep(0.05)
                if _drained:
                    print(f"drained {_drained} stale MQTT command(s) after reconnect", flush=True)

                now = time.time()
                last_heartbeat = now
                last_mqtt_ping = now
                last_frame_rx = now
                last_sensor_rx = now
                next_resubscribe  = now + REPORT_RESUBSCRIBE if REPORT_RESUBSCRIBE > 0 else 0
                next_bus_mask     = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0
                last_bus_refresh_sent = now  # debounce: evita invii bus_mask/bus_refresh troppo ravvicinati
                recv_buf = b""

                while True:
                    now = time.time()

                    # Nessun frame grezzo → device/WiFi in deep-sleep
                    if now - last_frame_rx >= FRAME_SILENCE_TIMEOUT:
                        raise RuntimeError(
                            f"no frames for {now - last_frame_rx:.0f}s — reconnecting"
                        )

                    # Frame arrivano ma nessun sensore decodificato → problema subscription/protocollo.
                    # Grace period post-comando: il device può bloccare il reporting per 60-120s
                    # mentre applica un comando (es. output_power che resetta l'inverter).
                    # Non riconnettiamo durante la grace per evitare di triggerare automazioni HA.
                    _grace_until = getattr(args, "_cmd_grace_until", 0) or 0
                    sensor_silence = now - last_sensor_rx
                    if args.freeze_detection_enabled and sensor_silence >= SENSOR_RECONNECT_AFTER and now >= _grace_until:
                        raise RuntimeError(
                            f"no sensor data for {now - last_sensor_rx:.0f}s — reconnecting"
                        )

                    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                        _send_frame(sock, args, encode_cmd(28727, _next_packet_id(args)))
                        last_heartbeat = now

                    if now - last_mqtt_ping >= MQTT_PING_INTERVAL:
                        mqtt.ping()
                        last_mqtt_ping = now

                    if getattr(args, "smart_sockets_enabled", True) and now >= next_smart_socket_poll:
                        _poll_smart_sockets(mqtt, args.topic, args)
                        requested_interval = int(getattr(args, "smart_socket_poll_interval", 20) or 20)
                        if requested_interval < 10 and not getattr(args, "_smart_socket_poll_warned", False):
                            print(
                                "smart_socket_poll_interval below 10s: clamped to 10s",
                                flush=True,
                            )
                            args._smart_socket_poll_warned = True
                        interval = max(10, requested_interval)
                        next_smart_socket_poll = now + interval

                    # Rinnova subscription: il device la dimentica se resta senza richiami.
                    # Anche durante il silenzio sensori continuiamo, come nel bridge 0.3.55:
                    # se blocchiamo questi richiami, la LAN resta ferma fino al recovery.
                    if REPORT_RESUBSCRIBE > 0 and now >= next_resubscribe:
                        send_report_subscription(sock, key, iv, args)
                        next_resubscribe = now + REPORT_RESUBSCRIBE

                    if BUS_MASK_INTERVAL > 0 and now >= next_bus_mask:
                        if now - last_bus_refresh_sent >= BUS_REFRESH_MIN_GAP:
                            send_bus_mask(sock, key, iv, args)
                            send_bus_refresh(sock, key, iv, args)
                            last_bus_refresh_sent = now
                        else:
                            _dprint(
                                f"bus_mask/bus_refresh periodico soppresso "
                                f"(debounce, {now - last_bus_refresh_sent:.1f}s fa)",
                                flush=True,
                            )
                        next_bus_mask = now + BUS_MASK_INTERVAL

                    for topic, payload, retained in mqtt.read_messages():
                        if retained:
                            _dprint(f"ignored retained MQTT command: {topic}={payload}", flush=True)
                            continue
                        if _handle_smart_socket_command(topic, payload, mqtt, args.topic, args):
                            continue
                        if not session_had_sensor_data:
                            print(f"command dropped (no sensor data yet): {topic}={payload}", flush=True)
                            continue
                        handle_mqtt_command(topic, payload, sock, mqtt, args.topic, key, iv, args)

                    if session_had_sensor_data:   # Bug 3 fix
                        _flush_pending_output_power(sock, mqtt, args.topic, key, iv, args)

                    kick_due = getattr(args, "_next_bus_kick", 0) or 0
                    if kick_due and now >= kick_due:
                        # Dopo ogni comando: bus_refresh + bus_mask completa (ids=31).
                        # Mantiene tutti i sensori attivi senza restringere la mask a batteria/base.
                        if now - last_bus_refresh_sent >= BUS_REFRESH_MIN_GAP:
                            send_bus_refresh(sock, key, iv, args)
                            send_bus_mask(sock, key, iv, args)
                            last_bus_refresh_sent = now
                        else:
                            _dprint(
                                f"bus_mask/bus_refresh post-comando soppresso "
                                f"(debounce, {now - last_bus_refresh_sent:.1f}s fa)",
                                flush=True,
                            )
                        args._next_bus_kick = 0
                        next_bus_mask = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0

                    # ── Receive and decode LAN frames ────────────────────────
                    data = recv_some(sock, 0.2)
                    if data:
                        last_frame_rx = time.time()
                        recv_buf += data

                    if not recv_buf:
                        continue

                    frames, recv_buf = extract_frames(recv_buf)
                    if not frames and len(recv_buf) > 8192:
                        print(f"LAN recv buffer discarded ({len(recv_buf)} bytes without frame)", flush=True)
                        recv_buf = b""

                    for frame in frames:
                        raw_payload = frame.get("payload", b"")
                        if not frame.get("checksum_ok"):
                            _dprint(
                                f"ignored LAN frame with bad checksum: "
                                f"cmd={frame.get('cmd')} packet={frame.get('packet_id')}",
                                flush=True,
                            )
                            continue
                        if not raw_payload or len(raw_payload) % 16:
                            continue
                        try:
                            plain = aes_decrypt(raw_payload, key, iv)
                        except Exception:
                            continue

                        # output_power_set puo' arrivare in frame LAN di stato brevi
                        # che non contengono altri sensori: aggiorna subito lo slider.
                        lan_power_state = {}
                        _extract_output_power_set(plain, lan_power_state)
                        if "output_power_set" in lan_power_state:
                            publish_output_power_state(
                                mqtt,
                                args.topic,
                                lan_power_state["output_power_set"],
                                "LAN",
                                args,
                            )

                        charge_power = _extract_intelligent_charging_power(plain)
                        if charge_power is not None and _command_state_allowed(
                            args, INTELLIGENT_CHARGING_POWER_ID, str(charge_power)
                        ):
                            mqtt.publish(
                                f"{args.topic}/cmd_state/{INTELLIGENT_CHARGING_POWER_ID}",
                                str(charge_power),
                                retain=True,
                            )

                        decoded = decode_bus_payload(plain)
                        # TSL-driven walker: integra i campi ricavati dal TSL che
                        # il decoder principale non espone direttamente.
                        try:
                            from landbook_ttlv_walker import decode_payload as _ttlv_decode
                            walker_out = _ttlv_decode(plain) or {}
                        except Exception as _exc:
                            walker_out = {}
                            print(f"ttlv walker error: {_exc}", flush=True)
                        if walker_out:
                            # Non sovrascrivere campi già normalizzati in etichette
                            # leggibili, altrimenti HA oscillerebbe tra label e valore raw.
                            _LABELED_BY_LEGACY = {
                                "fault_code", "fault_code_raw",
                                "device_status", "device_status_raw",
                                "device_status_corrected",
                                "mode",
                                "high_frequency_reporting",
                            }
                            for k, v in walker_out.items():
                                if k in _LABELED_BY_LEGACY:
                                    continue
                                decoded[k] = v
                            # Alcuni codici (es. led_status_set) vengono riportati dal
                            # firmware in modo incoerente tra il frame "work_profile"
                            # completo e i frame brevi solo-batteria: nello stesso ciclo
                            # di polling l'uno dice ON, l'altro OFF. Per questi codici
                            # ci fidiamo solo del frame work_profile (quello che il
                            # firmware aggiorna in modo affidabile dopo un comando) e
                            # ignoriamo il valore quando arriva da un frame senza
                            # work_profile, invece di pubblicare ogni lettura e far
                            # sfarfallare l'entità HA tra i due stati.
                            _has_work_profile = "work_profile" in decoded
                            for _code in SWITCH_HEX:
                                if _code not in walker_out:
                                    continue
                                if _code in FRAME_COHERENCE_REQUIRES_WORK_PROFILE and not _has_work_profile:
                                    continue
                                _state = "ON" if bool(walker_out[_code]) else "OFF"
                                if _command_state_allowed(args, _code, _state):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", _state, retain=True)
                            # Translate raw int values to TSL labels for any code
                            # exposed as a HA select entity, then publish them as
                            # the entity state so HA shows the human-readable
                            # option (e.g. led_status_set=3 → "SOS").
                            #
                            # The TTLV wire format encodes "integer 0" and "bool
                            # false" with the same compact tag (and "integer 1"
                            # can collapse onto "bool true" too) — the firmware
                            # picks whichever encoding is shortest. So a BOOL
                            # value here isn't actually ambiguous: it's always
                            # literal index 0 (False) or 1 (True), regardless of
                            # how many options the ENUM has. Translate before
                            # the label lookup instead of discarding it.
                            _select_cat = getattr(args, "_tsl_select_catalog", {}) or {}
                            for _code, _info in _select_cat.items():
                                if _code not in walker_out:
                                    continue
                                if _code in FRAME_COHERENCE_REQUIRES_WORK_PROFILE and not _has_work_profile:
                                    continue
                                _opts = _info.get("options") or {}
                                _raw = walker_out[_code]
                                if isinstance(_raw, bool):
                                    _raw = 1 if _raw else 0
                                try:
                                    _label = _opts.get(int(_raw))
                                except (TypeError, ValueError):
                                    _label = None
                                if _label and _command_state_allowed(args, _code, _label):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", _label, retain=True)
                            _number_cat = getattr(args, "_tsl_number_catalog", {}) or {}
                            for _code in _number_cat:
                                if _code not in walker_out:
                                    continue
                                _nval = walker_out[_code]
                                # output_power_set can arrive as the TSL raw x10 value
                                # (e.g. 1000 for 100 W). Never publish it out of the HA
                                # number range, or HA logs "Invalid value ... (range ...)".
                                if _code == "output_power_set":
                                    _nval = _normalize_output_power_state_value(_nval)
                                    if _nval is None:
                                        continue
                                if _command_state_allowed(args, _code, str(_nval)):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", str(_nval), retain=True)
                        if decoded:
                            decoded.pop("high_frequency_reporting", None)
                            if not args.show_firmware_sensors:
                                decoded = {k: v for k, v in decoded.items() if k not in FIRMWARE_SENSOR_IDS}
                            if decoded:
                                meaningful_sensor_data = _has_meaningful_sensor_data(decoded, args)
                                if meaningful_sensor_data:
                                    last_sensor_rx = time.time()
                                    if "hmi_field1_raw" in decoded:
                                        args._last_field1_seen = decoded["hmi_field1_raw"]
                                    if "hmi_field2_uptime_candidate" in decoded:
                                        _new_uptime = decoded["hmi_field2_uptime_candidate"]
                                        _prev_uptime = getattr(args, "_last_uptime_seen", None)
                                        if _prev_uptime is not None and _new_uptime < _prev_uptime:
                                            print(
                                                f"hmi_field2_uptime_candidate è SCESO ({_prev_uptime} -> {_new_uptime}): "
                                                "possibile riavvio interno del device, non solo un freeze del reporting",
                                                flush=True,
                                            )
                                        args._last_uptime_seen = _new_uptime
                                    if sensor_silence_since is not None:
                                        print(
                                            f"freeze terminato dopo {last_sensor_rx - sensor_silence_since:.0f}s "
                                            f"(hmi_field1={getattr(args, '_last_field1_seen', '?')}, "
                                            f"hmi_field2_uptime_candidate={getattr(args, '_last_uptime_seen', '?')})",
                                            flush=True,
                                        )
                                    sensor_silence_since = None
                                    sensor_silence_streak = 0
                                    first_alert_at_episode = None
                                    args._cmd_grace_until = 0   # dati arrivati → grace non più necessaria
                                    if not session_had_sensor_data:
                                        session_had_sensor_data = True
                                        # Dati reali ricevuti: broken-pipe loop terminato
                                        if broken_pipe_since is not None:
                                            print(
                                                f"broken-pipe loop terminato dopo "
                                                f"{time.time() - broken_pipe_since:.0f}s — dati ricevuti",
                                                flush=True,
                                            )
                                        broken_pipe_since = None
                                else:
                                    _dprint(f"ignored non-meaningful decoded payload: {decoded}", flush=True)

                            alias_keys = apply_tsl_preferred_aliases(decoded)
                            zero_baseline_keys = apply_dc_sensor_zero_baseline(sensor_cache, decoded)
                            cell_voltage_keys = apply_cell_voltage_total_fallback(sensor_cache, decoded)
                            zero_values = zero_sensor_values_for_frame(sensor_cache, decoded)
                            if zero_values:
                                decoded.update(zero_values)
                            suppress_transient_ac_zeros(sensor_cache, decoded, args)

                            remaining_frame_keys = normalize_remaining_time_from_frame(decoded, sensor_cache)
                            guard_zero_remaining_time(decoded, sensor_cache)
                            explicit_override_keys = apply_explicit_switch_sensor_overrides(decoded, sensor_cache)
                            sensor_cache.update(decoded)
                            publish_keys = set(decoded)
                            publish_keys.update(remaining_frame_keys)
                            publish_keys.update(alias_keys)
                            publish_keys.update(zero_baseline_keys)
                            publish_keys.update(cell_voltage_keys)
                            publish_keys.update(explicit_override_keys)
                            apply_derived_sensors(sensor_cache)
                            publish_keys.update(apply_battery_capacity_sensors(sensor_cache, decoded, args))
                            publish_keys.update(apply_grid_frequency_default(sensor_cache, decoded, args))
                            if any(k in decoded for k in ("pv_input_power", "ac_input_power")):
                                publish_keys.add("total_input_power")
                            if any(k in decoded for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
                                publish_keys.add("total_output_power")
                            publish_keys.update(apply_battery_power_balance(sensor_cache, decoded, args))
                            publish_keys.update(apply_device_status_correction(sensor_cache, decoded))
                            publish_keys.update(apply_raw_status_labels(sensor_cache, decoded))
                            sensor_cache["updated_at"] = int(time.time())
                            publish_sensor_cache(mqtt, args.topic, sensor_cache, publish_keys, args)
                            if "output_power_set" in decoded:
                                publish_output_power_state(mqtt, args.topic, decoded["output_power_set"], "LAN decoded", args)
                            publish_inferred_command_states(mqtt, args.topic, sensor_cache, decoded, args)
                            if decoded:
                                debug_decoded = dict(decoded)
                                _dprint(f"decoded: {debug_decoded}", flush=True)

                        reported = extract_reported_command_states(plain) if len(plain) <= 96 else {}
                        if reported:
                            if "output_power" in reported:
                                publish_output_power_state(mqtt, args.topic, reported["output_power"], "LAN reported", args)
                            publish_reported_command_states(mqtt, args.topic, reported, args)
                            override_keys = apply_reported_sensor_overrides(sensor_cache, reported)
                            if override_keys:
                                sensor_cache["updated_at"] = int(time.time())
                                publish_sensor_cache(mqtt, args.topic, sensor_cache, override_keys, args)

            except MqttConnectionError as exc:
                print(f"MQTT error: {exc} — restarting bridge", flush=True)
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None
                try:
                    mqtt.disconnect()
                except Exception:
                    pass
                _restart_process(args)

            except (OSError, RuntimeError) as exc:
                now = time.time()
                exc_text = str(exc).lower()

                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None

                # ── WiFi freeze detection ─────────────────────────────────────
                # Silenzio sensori per 60s mentre il TCP è vivo = WiFi freeze.
                # Può accadere sia a inizio sessione (zombie puro) sia a metà
                # sessione (freeze progressivo): contiamo entrambi i casi.
                is_sensor_silence = (
                    bool(getattr(args, "freeze_detection_enabled", True)) and
                    ("no sensor data" in exc_text or "no frames" in exc_text)
                )
                exc_errno = getattr(exc, "errno", None)
                reset_errnos = {getattr(errno, "ECONNRESET", 104), 10054}
                reset_errnos.discard(None)
                is_lan_reset = (
                    exc_errno in reset_errnos or
                    isinstance(exc, ConnectionResetError) or
                    any(s in exc_text for s in (
                        "connection reset by peer",
                        "connection reset",
                        "forcibly closed",
                    ))
                )
                is_hard_unreachable = (
                    exc_errno in {errno.EHOSTUNREACH, errno.ENETUNREACH} or
                    any(s in exc_text for s in (
                        "host is unreachable",
                        "network is unreachable",
                        "no route to host",
                        "timed out",
                    ))
                )
                if is_sensor_silence:
                    # BUGFIX 0.3.52:
                    # prima lo streak veniva incrementato SOLO se la sessione aveva già
                    # ricevuto sensori. Quando invece il reconnect creava sessioni mute,
                    # "wifi_frozen" non partiva mai. Ora contiamo entrambe le condizioni.
                    if sensor_silence_since is None:
                        sensor_silence_since = now
                        _prev_freeze_start = getattr(args, "_last_freeze_start", None)
                        _gap_txt = (
                            f", {now - _prev_freeze_start:.0f}s dal freeze precedente"
                            if _prev_freeze_start else ""
                        )
                        print(
                            f"FREEZE START {time.strftime('%H:%M:%S', time.localtime(now))}"
                            f" (uptime_candidate={getattr(args, '_last_uptime_seen', '?')}{_gap_txt})",
                            flush=True,
                        )
                        args._last_freeze_start = now
                    sensor_silence_streak += 1
                    if not session_had_sensor_data:
                        print(
                            f"LAN sessione muta: nessun sensore ricevuto prima del reconnect "
                            f"(freeze streak={sensor_silence_streak})",
                            flush=True,
                        )
                    else:
                        print(
                            f"WiFi reporting freeze? streak={sensor_silence_streak} "
                            "(sessione aveva dati, poi congelata)",
                            flush=True,
                        )
                    if sensor_silence_streak >= WIFI_FROZEN_ALERT_AFTER:
                        about_to_stop = sensor_silence_streak >= WIFI_FROZEN_STOP_AFTER
                        alert_elapsed = now - last_wifi_frozen_alert
                        if last_wifi_frozen_alert and alert_elapsed < WIFI_FROZEN_ALERT_COOLDOWN \
                                and not about_to_stop:
                            print(
                                f"MQTT wifi_frozen alert soppresso "
                                f"(cooldown {WIFI_FROZEN_ALERT_COOLDOWN - alert_elapsed:.0f}s)",
                                flush=True,
                            )
                        else:
                            try:
                                publish_wifi_frozen_alert(
                                    mqtt,
                                    args.topic,
                                    reason="sensor_silence",
                                    streak=sensor_silence_streak,
                                    duration=now - sensor_silence_since,
                                )
                                print(
                                    f"MQTT wifi_frozen alert pubblicato (streak={sensor_silence_streak})",
                                    flush=True,
                                )
                                last_wifi_frozen_alert = now
                                if first_alert_at_episode is None:
                                    first_alert_at_episode = now
                            except Exception as me:
                                print(f"MQTT wifi_frozen publish failed: {me}", flush=True)
                    if sensor_silence_streak >= WIFI_FROZEN_STOP_AFTER:
                        _since_first_alert = (
                            now - first_alert_at_episode if first_alert_at_episode else 0.0
                        )
                        if first_alert_at_episode is not None and _since_first_alert < MIN_SECONDS_BEFORE_STOP:
                            _dprint(
                                f"Freeze streak={sensor_silence_streak} ma attendo ancora "
                                f"{MIN_SECONDS_BEFORE_STOP - _since_first_alert:.0f}s "
                                "(tempo per l'automazione di riavvio WiFi) prima di spegnere l'add-on",
                                flush=True,
                            )
                        else:
                            stop_addon_after_freeze(
                                mqtt,
                                availability_topic,
                                args.topic,
                                sensor_silence_streak,
                                now - sensor_silence_since,
                            )

                    if now - sensor_silence_since >= SENSOR_SILENCE_RESTART:
                        print(
                            f"Sensori assenti da {now - sensor_silence_since:.0f}s — availability offline e riavvio bridge",
                            flush=True,
                        )
                        try:
                            mqtt.publish_resilient(availability_topic, "offline", retain=True)
                            availability_offline_sent = True
                        except Exception as exc:
                            print(f"MQTT availability offline publish failed: {exc}", flush=True)
                        try:
                            mqtt.disconnect()
                        except Exception:
                            pass
                        _restart_process(args)
                else:
                    # Un 'host unreachable' / 'timed out' / RST subito dopo un alert
                    # wifi_frozen è l'effetto ATTESO dell'automazione HA che ha appena
                    # spento il WiFi 2.4G del router per il recovery. Se in quel momento
                    # azzeriamo lo streak, l'episodio di freeze non raggiunge mai
                    # WIFI_FROZEN_STOP_AFTER: wifi_frozen viene ripubblicato ad OGNI ciclo
                    # (~60-90s) all'infinito e l'automazione thrasha la WiFi di casa
                    # (migliaia di toggle). Durante un episodio di freeze attivo NON
                    # resettiamo su unreachable/reset: lo streak/episodio si azzera solo
                    # quando tornano dati sensori reali (ramo di ricezione sopra).
                    _in_freeze_episode = sensor_silence_since is not None
                    _recovery_disconnect = is_hard_unreachable or is_lan_reset
                    if _in_freeze_episode and _recovery_disconnect:
                        _dprint(
                            f"disconnessione attesa durante recovery freeze "
                            f"(streak={sensor_silence_streak}) — episodio mantenuto, nessun reset",
                            flush=True,
                        )
                    else:
                        if sensor_silence_streak > 0:
                            print(f"WiFi freeze streak reset (era {sensor_silence_streak})", flush=True)
                        sensor_silence_streak = 0
                        sensor_silence_since = None

                if "mqtt disconnected" in exc_text:
                    print("MQTT disconnected - restarting bridge", flush=True)
                    _restart_process(args)

                if is_lan_reset:
                    print("LAN RST ricevuto dalla powerstation; socket chiuso e riconnessione in corso", flush=True)

                # Detect hard unreachability (WiFi/network down, not just device)
                if is_hard_unreachable:
                    if unreachable_since is None:
                        unreachable_since = now
                        _prev_unreachable_start = getattr(args, "_last_unreachable_start", None)
                        _gap_txt = (
                            f", {now - _prev_unreachable_start:.0f}s dall'unreachable precedente"
                            if _prev_unreachable_start else ""
                        )
                        print(
                            f"UNREACHABLE START {time.strftime('%H:%M:%S', time.localtime(now))}"
                            f" (uptime_candidate={getattr(args, '_last_uptime_seen', '?')}{_gap_txt})",
                            flush=True,
                        )
                        args._last_unreachable_start = now
                else:
                    unreachable_since = None

                # Detect broken-pipe loop (device accepts TCP but drops immediately after login)
                is_broken_pipe = (
                    exc_errno == errno.EPIPE or "broken pipe" in exc_text
                )
                if is_broken_pipe:
                    if broken_pipe_since is None:
                        broken_pipe_since = now
                elif not is_sensor_silence:
                    # Bug 1 fix: non azzerare broken_pipe_since su sensor-silence
                    # (wifi-frozen). Se il device alterna broken-pipe → wifi-frozen
                    # senza mai dare dati, il timer deve restare attivo.
                    # Viene resettato solo quando arrivano dati reali (vedi sopra).
                    broken_pipe_since = None

                print(f"LAN error: {exc}; reconnecting in {reconnect_delay:.0f}s", flush=True)

                if unreachable_since is not None:
                    unreachable_elapsed = now - unreachable_since
                    if unreachable_elapsed >= UNREACHABLE_WIFI_FROZEN_ALERT:
                        _dprint(
                            f"LAN unreachable da {unreachable_elapsed:.0f}s: "
                            "riconnessione in corso senza evento wifi_frozen",
                            flush=True,
                        )

                # Restart the process if the network has been hard-unreachable too long
                # (handles the case where the WiFi router takes >3 min to come back)
                if unreachable_since is not None and now - unreachable_since >= UNREACHABLE_RESTART:
                    print(f"LAN unreachable for {now - unreachable_since:.0f}s — restarting bridge", flush=True)
                    try:
                        mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                    except Exception:
                        pass
                    _restart_process(args)

                # Restart the process if stuck in a broken-pipe loop
                # (device firmware accepts TCP but drops connection after login;
                #  a fresh process start breaks the cycle, same as manual restart)
                if broken_pipe_since is not None and now - broken_pipe_since >= BROKEN_PIPE_RESTART:
                    print(f"Broken-pipe loop for {now - broken_pipe_since:.0f}s — restarting bridge", flush=True)
                    try:
                        mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                    except Exception:
                        pass
                    _restart_process(args)

                # Refresh LAN key on auth failure (unbind/rebind dall'app).
                # The cached key is stale → wipe it before asking the cloud for a fresh one,
                # so even if the refresh fails the next addon restart won't use the bad cache.
                if "login failed" in exc_text:
                    print("Login failed — invalidating cached LAN key and refreshing from cloud", flush=True)
                    _invalidate_lan_key_cache()
                    _refresh_lan_key(args)

                if lan_disconnected_since is None:
                    lan_disconnected_since = now

                # Hold MQTT "online" for short WiFi restarts; go offline only after AVAILABILITY_HOLD.
                # Broken-pipe = device accetta TCP ma chiude subito (boot state) → raggiungibile.
                # Sensor-silence = WiFi freeze, TCP vivo → raggiungibile.
                # In entrambi i casi il bridge auto-si-riavvia e torna online: NON andare offline.
                # Offline solo su hard-unreachable (rete giù) o su altri errori prolungati.
                elapsed = now - lan_disconnected_since
                if not availability_offline_sent and elapsed >= AVAILABILITY_HOLD \
                        and not is_broken_pipe and not is_sensor_silence and not is_lan_reset:
                    try:
                        mqtt.publish_resilient(availability_topic, "offline", retain=True)
                        availability_offline_sent = True
                        print(f"MQTT availability → offline after {elapsed:.0f}s outage", flush=True)
                    except Exception as exc:
                        print(f"MQTT availability offline publish failed: {exc}", flush=True)

                # Wait, checking offline trigger every second during the delay
                sleep_until = time.time() + reconnect_delay
                while time.time() < sleep_until:
                    if not availability_offline_sent and lan_disconnected_since is not None \
                            and not is_broken_pipe and not is_sensor_silence and not is_lan_reset:
                        if time.time() - lan_disconnected_since >= AVAILABILITY_HOLD:
                            try:
                                mqtt.publish_resilient(availability_topic, "offline", retain=True)
                                availability_offline_sent = True
                            except Exception as exc:
                                print(f"MQTT availability offline publish failed: {exc}", flush=True)
                    time.sleep(min(1.0, max(0.0, sleep_until - time.time())))

                reconnect_delay = min(reconnect_delay * 1.5, RECONNECT_DELAY_MAX)

    finally:
        try:
            mqtt.publish(availability_topic, "offline", retain=True)
        except Exception as exc:
            print(f"MQTT availability offline publish failed on exit: {exc}", flush=True)
        try:
            mqtt.disconnect()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Landbook/Wonderfree generic LAN -> HA MQTT bridge")
    parser.add_argument("--device-host", default="")
    parser.add_argument("--device-port", type=int, default=6607)
    parser.add_argument("--key", required=True, help="LAN key (base64). Retrieved by addon_run.py from the cloud or local cache.")
    parser.add_argument("--mqtt-host", default="core-mosquitto")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-user")
    parser.add_argument("--mqtt-password")
    parser.add_argument("--device-key", default=os.environ.get("DEVICE_KEY", DEVICE_KEY))
    parser.add_argument("--topic", default=f"landbook/{DEVICE_KEY}")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--report-interval", type=int, default=10)
    parser.add_argument("--battery-capacity-wh", type=float, default=2048)
    parser.add_argument("--battery-cache-path", default="/data/landbook_battery_cache.json")
    parser.add_argument("--battery-current-fallback-voltage", type=float, default=52.8)
    parser.add_argument("--grid-frequency-default", type=float, default=50)
    parser.add_argument("--ac-zero-hold-seconds", type=float, default=18)
    parser.add_argument("--show-firmware-sensors", action="store_true", default=False)
    parser.add_argument("--smart-sockets-enabled", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--smart-socket-poll-interval", type=int, default=20)
    parser.add_argument("--smart-socket-1-device-key", default="")
    parser.add_argument("--smart-socket-1-product-key", default="")
    parser.add_argument("--smart-socket-1-name", default="")
    parser.add_argument("--smart-socket-2-device-key", default="")
    parser.add_argument("--smart-socket-2-product-key", default="")
    parser.add_argument("--smart-socket-2-name", default="")
    parser.add_argument("--output-power-min", type=int, default=100)
    parser.add_argument("--output-power-max", type=int, default=800)
    parser.add_argument("--output-power-step", type=int, default=10)
    parser.add_argument("--output-power-debounce", type=float, default=0.25)
    parser.add_argument("--device-tx-min-interval", type=float, default=0.6)
    parser.add_argument("--command-duplicate-window", type=float, default=COMMAND_DUPLICATE_WINDOW)
    parser.add_argument("--command-opposite-window", type=float, default=COMMAND_OPPOSITE_WINDOW)
    parser.add_argument("--mqtt-stale-drain-seconds", type=float, default=2.0)
    parser.add_argument(
        "--freeze-detection-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Se False, disabilita la riconnessione automatica per 'silenzio sensori' "
             "(SENSOR_RECONNECT_AFTER) — utile per testare se il ciclo naturale Low/LAN+WiFi "
             "del device viene scambiato per un freeze reale. Non tocca il controllo 'no frames' "
             "(LAN davvero morta), che resta sempre attivo. Default True = comportamento invariato.",
    )
    args = parser.parse_args()
    print(f"Landbook LAN MQTT Bridge {APP_VERSION} starting", flush=True)
    run(args)


if __name__ == "__main__":
    main()
