"""
Landbook FPPT-T2400 — LAN to Home Assistant MQTT bridge  v0.3.79-fixed

Design: connect → subscribe(10s) → bus_mask(8s) → bus_refresh(20s) → recv loop → reconnect on silence/error
Report subscription renewed every 60s (device forgets it after ~60s).
MQTT alert after consecutive sensor-silence reconnects, including fully mute sessions.
"""

import argparse
import base64
import errno
import json
import os
import socket
import sys
import threading
import time
from typing import Any

from landbook_lan_probe import encode_cmd, hexs, iter_frames, recv_some
from landbook_local_client import DEFAULT_KEY, aes_decrypt, aes_encrypt, connect_and_login, ttlv_number


def _is_debug():
    return os.environ.get("LANDBOOK_LOG_LEVEL", "info").lower() == "debug"

def _dprint(*args, **kwargs):
    if _is_debug():
        import builtins
        builtins.print(*args, **kwargs)


# ── Timing ───────────────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL     = 10    # LAN keepalive (seconds)
MQTT_PING_INTERVAL     = 30    # MQTT keepalive
FRAME_SILENCE_TIMEOUT  = 30    # come 0.2.7 veloce: tollera il ciclo bus_mask
SENSOR_SOFT_SUBSCRIBE_AFTER = 0   # disattivato: la 0.2.7 veloce usa polling bus_mask
SENSOR_SOFT_REFRESH_AFTER   = 0   # disattivato: evita recovery tardivi e doppi
SENSOR_RECONNECT_AFTER      = 40  # freeze rapido: reconnect/evento se nessun sensore
SENSOR_SILENCE_TIMEOUT = SENSOR_RECONNECT_AFTER
SENSOR_SILENCE_RESTART = 180  # dopo 3 min senza sensori: riavvio processo
STARTUP_PRIMER_SUBSCRIBE_AFTER = 12  # sessione nata muta: ritenta presto la subscription
STARTUP_PRIMER_MASK_AFTER      = 25  # sessione nata muta: richiedi solo i dati batteria/base
REPORT_RESUBSCRIBE     = 120   # come 0.2.7 veloce: subscription rara
BUS_MASK_INTERVAL      = 8     # logica veloce: full mask + refresh ogni 8s
BUS_REFRESH_INTERVAL   = 30    # refresh standalone, ridondante rispetto a bus_mask
FULL_BUS_MASK_COOLDOWN = 0     # 0.3.75: su sessione muta serve sempre ids=31 per riattivare i report
# BATTERY_MASK_INTERVAL rimosso: 0x0003/0x0004 già inclusi in BUS_MASK_IDS(31);
# il bus_mask periodico con 2 IDs causava WiFi freeze ogni 30s
RECONNECT_DELAY_INIT   = 2.0   # recovery LAN rapido dopo freeze/unreachable
RECONNECT_DELAY_MAX    = 5.0   # non aspettare 17/25/30s tra retry
UNREACHABLE_RESTART    = 180   # restart process after 3 min unreachable
BROKEN_PIPE_RESTART    = 30    # restart process after 30s broken-pipe loop
FAULT_RECOVERY_MAX     = 3     # max retrigger E02 per sessione (evita loop)
AVAILABILITY_HOLD      = 300   # hold MQTT "online" for 5 min during outage
# ── WiFi freeze detection ─────────────────────────────────────────────────────
# Il modulo WiFi della powerstation può congelare il task di reporting mantenendo
# il TCP vivo (gli switch continuano a funzionare ma i sensori non arrivano).
# Dopo WIFI_FROZEN_ALERT_AFTER: pubblica evento MQTT per automazioni HA.
WIFI_FROZEN_ALERT_AFTER  = 1     # evento MQTT subito dopo circa 40s senza sensori
WIFI_FROZEN_ALERT_COOLDOWN = 300 # evita riavvii router troppo frequenti


# ── Device identity ──────────────────────────────────────────────────────────
DEVICE_KEY   = "000000000000"
DEVICE_NAME  = "Landbook FPPT-T2400"
APP_VERSION  = "0.3.80"
OUTPUT_POWER_TAG = 0x00EA
BUS_REFRESH_TAG  = 0x009A
BUS_MASK_IDS = [
    0x001E, 0x0027, 0x0021, 0x001C, 0x0020, 0x0026, 0x0022, 0x001F,
    0x000B, 0x001D, 0x0010, 0x0011, 0x000D, 0x000A, 0x0005,
    0x0008, 0x0009, 0x0003, 0x0006, 0x0002, 0x001B, 0x0010, 0x0001,
    0x000F, 0x000C, 0x0011, 0x000E, 0x0004, 0x0012, 0x0029, 0x002A,
]
BATTERY_MASK_IDS = [0x0003, 0x0004]


# ── Switch / mode tables ─────────────────────────────────────────────────────
SWITCH_HEX = {
    "led": {
        "name": "LED",
        "on":  "AA AA 00 09 A9 02 8F 00 13 01 02 00 01",
        "off": "AA AA 00 09 A9 02 90 00 13 01 02 00 00",
    },
    "ac": {
        "name": "Presa AC",
        "on":  "AA AA 00 07 A5 00 20 00 13 00 71",
        "off": "AA AA 00 07 C7 00 43 00 13 00 70",
    },
    "dc": {
        "name": "DC",
        "on":  "AA AA 00 07 17 02 88 00 13 00 79",
        "off": "AA AA 00 07 15 02 87 00 13 00 78",
    },
    "screen": {
        "name": "Screen",
        "on":  "AA AA 00 09 40 00 F9 00 13 01 32 00 00",
        "off": "AA AA 00 09 2F 00 DE 00 13 01 32 00 0A",
    },
    "grid": {
        "name": "Uscita Watt",
        "on":  "AA AA 00 07 28 01 32 00 13 00 E1",
        "off": "AA AA 00 07 24 01 2F 00 13 00 E0",
    },
    "beep": {
        "name": "Beep",
        "on":  "AA AA 00 07 0C 01 BD 00 13 01 39",
        "off": "AA AA 00 07 08 01 BA 00 13 01 38",
    },
    "slow_reporting": {
        "name": "Ricarica AC lenta",
        "on":  "AA AA 00 07 06 01 E7 00 13 01 09",
        "off": "AA AA 00 07 FD 01 DF 00 13 01 08",
    },
}

MODE_HEX_BY_LABEL = {
    "PPS":                    "AA AA 00 09 06 00 19 00 13 00 DA 00 00",
    "Micro-Inverter":         "AA AA 00 09 08 00 1A 00 13 00 DA 00 01",
    "Power Reserve Priority": "AA AA 00 09 76 02 84 00 13 00 DA 00 02",
}
MODE_LABEL_BY_VAL = {0: "PPS", 1: "Micro-Inverter", 2: "Power Reserve Priority"}

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
# come fault solo i codici presenti nel TSL ufficiale del T2400.
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

SWITCH_DISCOVERY_META = {
    "ac":           {"icon": "mdi:power-socket-eu"},
    "dc":           {"icon": "mdi:current-dc"},
    "grid":         {"icon": "mdi:transmission-tower-export"},
    "led":          {"icon": "mdi:led-on"},
    "screen":       {"icon": "mdi:monitor"},
    "beep":         {"icon": "mdi:volume-high"},
    "slow_reporting": {"icon": "mdi:battery-charging-low"},
}
NON_CACHED_SWITCH_IDS = set(SWITCH_HEX.keys()) | {"mode"}


# ── Sensor definitions ───────────────────────────────────────────────────────
SENSOR_DEFS = {
    "battery_percentage":           ("Battery",              "%",   "battery",     "measurement"),
    "battery_voltage":              ("Battery Voltage",      "V",   "voltage",     "measurement"),
    "battery_current":              ("Battery Current",      "A",   "current",     "measurement"),
    "battery_temp":                 ("Battery Temp",         "°C",  "temperature", "measurement"),
    "battery_total_power":          ("Battery Power",        "W",   "power",       "measurement"),
    "battery_remaining_wh":         ("Battery Remaining",    "Wh",  "energy",      None),
    "remaining_time_minutes":       ("Tempo residuo",        "h",   "duration",    "measurement"),
    "pv_input_power":               ("PV Power",             "W",   "power",       "measurement"),
    "pv_panel_voltage":             ("PV Panel Voltage",     "V",   "voltage",     "measurement"),
    "grid_voltage":                 ("Grid Voltage",         "V",   "voltage",     "measurement"),
    "grid_freq":                    ("Grid Frequency",       "Hz",  "frequency",   "measurement"),
    "grid_b_power":                 ("Micro-Inverter Power", "W",   "power",       "measurement"),
    "ac_input_power":               ("AC Input Power",       "W",   "power",       "measurement"),
    "ac_output_power":              ("AC/uscita watt",       "W",   "power",       "measurement"),
    "dc_output_power":              ("DC Output Power",      "W",   "power",       "measurement"),
    "usb_a1_voltage":               ("USB A1 Voltage",       "V",   "voltage",     "measurement"),
    "usb_a1_power":                 ("USB A1 Power",         "W",   "power",       "measurement"),
    "usb_a1_current":               ("USB A1 Current",       "A",   "current",     "measurement"),
    "usb_a2_voltage":               ("USB A2 Voltage",       "V",   "voltage",     "measurement"),
    "usb_a2_power":                 ("USB A2 Power",         "W",   "power",       "measurement"),
    "usb_a2_current":               ("USB A2 Current",       "A",   "current",     "measurement"),
    "usb_a3_voltage":               ("USB A3 Voltage",       "V",   "voltage",     "measurement"),
    "usb_a3_power":                 ("USB A3 Power",         "W",   "power",       "measurement"),
    "usb_a3_current":               ("USB A3 Current",       "A",   "current",     "measurement"),
    "usb_a4_voltage":               ("USB A4 Voltage",       "V",   "voltage",     "measurement"),
    "usb_a4_power":                 ("USB A4 Power",         "W",   "power",       "measurement"),
    "usb_a4_current":               ("USB A4 Current",       "A",   "current",     "measurement"),
    "typec_1_voltage":              ("Type-C 1 Voltage",     "V",   "voltage",     "measurement"),
    "typec_1_power":                ("Type-C 1 Power",       "W",   "power",       "measurement"),
    "typec_1_current":              ("Type-C 1 Current",     "A",   "current",     "measurement"),
    "typec_2_voltage":              ("Type-C 2 Voltage",     "V",   "voltage",     "measurement"),
    "typec_2_power":                ("Type-C 2 Power",       "W",   "power",       "measurement"),
    "typec_2_current":              ("Type-C 2 Current",     "A",   "current",     "measurement"),
    "dc12v_voltage":                ("DC 12V Voltage",       "V",   "voltage",     "measurement"),
    "dc12v_power":                  ("DC 12V Power",         "W",   "power",       "measurement"),
    "dc12v_current":                ("DC 12V Current",       "A",   "current",     "measurement"),
    "dc24v_voltage":                ("DC 24V Voltage",       "V",   "voltage",     "measurement"),
    "dc24v_power":                  ("DC 24V Power",         "W",   "power",       "measurement"),
    "dc24v_current":                ("DC 24V Current",       "A",   "current",     "measurement"),
    "temp_inv":                     ("Inverter Temp",        "°C",  "temperature", "measurement"),
    "temp_mppt":                    ("MPPT Temp",            "°C",  "temperature", "measurement"),
    "temp_bms":                     ("BMS Temp",             "°C",  "temperature", "measurement"),
    "total_input_power":            ("Total Input Power",    "W",   "power",       "measurement"),
    "total_output_power":           ("Total Output Power",   "W",   "power",       "measurement"),
    "device_status_raw":            ("Stato Device (num)",   None,  None,          None),
    "device_status":                ("Stato Device",         None,  None,          None),
    "fault_code":                   ("Codice Errore",        None,  None,          None),
    "fault_code_raw":               ("Codice Errore (num)",  None,  None,          None),
    "uptime_minutes_lan":           ("Uptime",               "min", "duration",    "total_increasing"),
    "firmware_version_set":         ("Firmware Main",        None,  None,          None),
    "firmware_version_bms":         ("Firmware BMS",         None,  None,          None),
    "firmware_version_mppt":        ("Firmware MPPT",        None,  None,          None),
    "firmware_version_inv":         ("Firmware INV",         None,  None,          None),
    "battery_cycles":               ("Battery Cycles",       None,  None,          "total_increasing"),
    "bms_allow_max_charge_current": ("BMS Max Charge Current","A",  "current",     "measurement"),
    "bms_mos_status":               ("BMS MOS Status",       None,  None,          None),
}
for _cell in range(1, 14):
    SENSOR_DEFS[f"battery_cell_{_cell:02d}_voltage"] = (f"Cell {_cell} Voltage", "V", "voltage", "measurement")

FIRMWARE_SENSOR_IDS = {"firmware_version_set", "firmware_version_bms", "firmware_version_mppt", "firmware_version_inv"}
BMS_CELL_SENSOR_IDS = {f"battery_cell_{c:02d}_voltage" for c in range(1, 14)}
BMS_INFO_SENSOR_IDS = BMS_CELL_SENSOR_IDS | {"battery_cycles", "bms_allow_max_charge_current", "bms_mos_status"}
BATTERY_INFO_SENSOR_IDS = {"battery_percentage", "battery_voltage", "battery_temp", "battery_remaining_wh", "remaining_time_minutes"}
BATTERY_CACHE_KEYS = BATTERY_INFO_SENSOR_IDS | {"_battery_soc_estimate_wh", "_battery_soc_estimate_ts"}
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
    "remaining_time_minutes": 2,
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

# ── MQTT discovery: object_id identici all'integrazione custom ────────────────
DEVICE_OBJECT_ID = "landbook_fppt_t2400"

SENSOR_OBJECT_ID_OVERRIDES = {
    "battery_percentage":     "battery",
    "remaining_time_minutes": "remaining_time",
    "grid_b_power":           "grid_power",
    "temp_inv":               "inverter_temp",
    "temp_mppt":              "mppt_temp",
    "temp_bms":               "bms_temp",
}

SWITCH_OBJECT_ID_OVERRIDES = {
    "ac":             "ac",
    "dc":             "dc",
    "led":            "led",
    "grid":           "grid_power",
    "beep":           "beep",
    "screen":         "screen",
    "slow_reporting": "slow_reporting",
}

_DIAGNOSTIC_SENSOR_IDS = {
    "device_status_raw", "fault_code_raw", "work_profile", "uptime_minutes_lan",
    "lan_status", "signal_strength_set", "temp_bms", "temp_inv", "temp_mppt",
    "bms_allow_max_charge_current", "bms_mos_status",
}
_DIAGNOSTIC_PREFIXES = ("battery_cell_", "usb_a", "typec_", "dc12v_", "dc24v_")


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


def _tag_battery_power(blob: bytes, tag: bytes):
    i = blob.find(tag)
    if i < 0 or i + 5 > len(blob):
        return None
    raw = blob[i + 2:i + 5]
    if raw[2] == 0 and raw[0] in (0x00, 0x80):
        return -raw[1] if raw[0] & 0x80 else raw[1]
    return _s16_prefixed(blob, i + 2)


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


def _marker_u16(blob: bytes, marker: bytes):
    i = blob.find(marker)
    return None if i < 0 else _u16(blob, i + len(marker))


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
    # hmi_data_no = "device_status, uptime_min, flags, fault_code, ..."
    # Confermato dal TSL cloud: field[0]=device_status, field[1]=uptime,
    # field[3]=fault_code. output_power_set NON è in field[4]: il cloud può
    # riportare 140W mentre hmi_data_no field[4] resta 0.
    try:
        fields = wp.split(",")
        if len(fields) < 2:
            return
        status = int(fields[0])
        uptime = int(fields[1])
        if 0 <= status <= 15:
            out["device_status_raw"] = status
            out["device_status"] = DEVICE_STATUS_LABELS.get(status, f"Stato {status}")
        if 0 <= uptime <= 100000:
            out["uptime_minutes_lan"] = uptime
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
            out["grid_b_power"] = power_raw
            if power_raw < 0:
                out["ac_input_power"] = abs(power_raw)
                out["ac_output_power"] = 0
            else:
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
        self.sock.sendall(header + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)

    def subscribe(self, topics):
        packet_id = self.next_packet_id
        self.next_packet_id += 1
        variable = packet_id.to_bytes(2, "big")
        payload = b"".join(_mqtt_string(t) + b"\x00" for t in topics)
        self.sock.sendall(b"\x82" + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)

    def ping(self):
        self.sock.sendall(b"\xC0\x00")

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
            chunk = self.sock.recv(4096)
            if chunk:
                self.rx.extend(chunk)
            else:
                raise RuntimeError("MQTT disconnected")
        except BlockingIOError:
            pass
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


def publish_discovery(mqtt, base_topic, args):
    device_key = _device_key(args)
    device = {
        "identifiers": [device_key],
        "name": DEVICE_NAME,
        "manufacturer": "Landbook",
        "model": "FPPT-T2400",
        "serial_number": device_key,
    }
    # Clean up any stale/obsolete sensor configs
    for sensor_id in ["output_power_set_guess", "soc_guess", "battery_cell_14_voltage",
                      "device_status_raw", "remaining_time_days", "pv_panel_power"]:
        mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", b"", retain=True)
    if not args.show_firmware_sensors:
        for sensor_id in FIRMWARE_SENSOR_IDS:
            mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", b"", retain=True)

    for sensor_id, (name, unit, device_class, state_class) in SENSOR_DEFS.items():
        if sensor_id in FIRMWARE_SENSOR_IDS and not args.show_firmware_sensors:
            continue
        object_id = f"{DEVICE_OBJECT_ID}_{SENSOR_OBJECT_ID_OVERRIDES.get(sensor_id, sensor_id)}"
        config = {
            "name": name,
            "object_id": object_id,
            "has_entity_name": True,
            "state_topic": f"{base_topic}/sensors/{sensor_id}",
            "unique_id": f"{device_key}_{sensor_id}_v2" if sensor_id == "remaining_time_minutes" else f"{device_key}_{sensor_id}",
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
            expire = int(getattr(args, "sensor_expire_after", 0) or 0)
            if sensor_id in BATTERY_INFO_SENSOR_IDS:
                expire = int(getattr(args, "battery_info_expire_after", expire) or expire)
            if expire > 0:
                config["expire_after"] = expire
        mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", json.dumps(config), retain=True)

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
        config.update(SWITCH_DISCOVERY_META.get(switch_id, {}))
        mqtt.publish(f"homeassistant/switch/{device_key}/{switch_id}/config", json.dumps(config), retain=True)

    mqtt.publish(f"homeassistant/select/{device_key}/mode/config", json.dumps({
        "name": "Modalita",
        "object_id": f"{DEVICE_OBJECT_ID}_mode",
        "has_entity_name": True,
        "command_topic": f"{base_topic}/set/mode",
        "state_topic": f"{base_topic}/cmd_state/mode",
        "options": list(MODE_HEX_BY_LABEL),
        "unique_id": f"{device_key}_mode",
        "device": device,
        "availability_topic": f"{base_topic}/availability",
    }), retain=True)

    mqtt.publish(f"homeassistant/number/{device_key}/output_power_set/config", json.dumps({
        "name": "Limite Micro-Inverter",
        "object_id": f"{DEVICE_OBJECT_ID}_output_power_set",
        "has_entity_name": True,
        "command_topic": f"{base_topic}/set/output_power",
        "state_topic": f"{base_topic}/cmd_state/output_power",
        "min": getattr(args, "output_power_min", 100),
        "max": getattr(args, "output_power_max", 800),
        "step": getattr(args, "output_power_step", 10),
        "mode": "slider",
        "unit_of_measurement": "W",
        "unique_id": f"{device_key}_output_power_set_number",
        "device": device,
        "availability_topic": f"{base_topic}/availability",
    }), retain=True)

    _dprint(f"published discovery {APP_VERSION}", flush=True)


def subscribe_command_topics(mqtt, base_topic):
    topics = [f"{base_topic}/set/{switch_id}" for switch_id in SWITCH_HEX]
    topics.append(f"{base_topic}/set/mode")
    topics.append(f"{base_topic}/set/output_power")
    mqtt.subscribe(topics)


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


def _transparent_parts(frame_hex):
    raw = bytes.fromhex(frame_hex.replace(" ", ""))
    if len(raw) < 9 or raw[:2] != b"\xAA\xAA":
        raise ValueError(f"invalid frame: {frame_hex}")
    body_len = int.from_bytes(raw[2:4], "big")
    if len(raw) != body_len + 4:
        raise ValueError(f"invalid frame length: {frame_hex}")
    return int.from_bytes(raw[7:9], "big"), raw[9:]  # cmd, payload


def _build_write_frame(frame_hex, key, iv, args):
    cmd, payload = _transparent_parts(frame_hex)
    return encode_cmd(cmd, _next_packet_id(args), aes_encrypt(payload, key, iv))


def _build_output_power_frame(watts, key, iv, args):
    payload = OUTPUT_POWER_TAG.to_bytes(2, "big") + b"\x01" + int(watts).to_bytes(2, "big")
    return encode_cmd(0x0013, _next_packet_id(args), aes_encrypt(payload, key, iv))


def send_bus_refresh(sock, key, iv, args, mode=3):
    payload = BUS_REFRESH_TAG.to_bytes(2, "big") + int(mode).to_bytes(2, "big")
    frame = encode_cmd(0x0013, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"sent bus_refresh mode={mode}", flush=True)


def send_bus_mask(sock, key, iv, args, ids=None):
    mask_ids = ids if ids is not None else BUS_MASK_IDS
    payload = b"".join(int(x).to_bytes(2, "big") for x in mask_ids)
    frame = encode_cmd(0x0011, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"sent bus_mask ids={len(mask_ids)}", flush=True)


def send_report_subscription(sock, key, iv, args):
    interval = int(getattr(args, "report_interval", 10) or 10)
    payload = ttlv_number(1, interval) + ttlv_number(2, 1)
    frame = encode_cmd(28729, _next_packet_id(args), aes_encrypt(payload, key, iv))
    _send_frame(sock, args, frame)
    _dprint(f"LAN report subscription sent (interval={interval}s)", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# Battery cache
# ══════════════════════════════════════════════════════════════════════════════

def load_battery_cache(args):
    return {}


def save_battery_cache(cache, decoded, args):
    return


SWITCH_CACHE_PATH = "/data/landbook_switch_cache.json"
_SWITCH_CACHE_KEYS = set(SWITCH_HEX.keys()) | {"mode"}


def load_switch_cache() -> dict:
    return {}


def save_switch_cache(states: dict) -> None:
    return


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


# ══════════════════════════════════════════════════════════════════════════════
# Sensor publishing
# ══════════════════════════════════════════════════════════════════════════════

def _sensor_value(key, value):
    if key == "remaining_time_minutes":
        try:
            hours = round(float(value) / 60.0, 2)
        except (TypeError, ValueError):
            return value
        return int(hours) if float(hours).is_integer() else hours
    return value


def publish_sensor_cache(mqtt, base_topic, cache, keys=None):
    sensor_ids = SENSOR_DEFS if keys is None else [k for k in keys if k in SENSOR_DEFS]
    for key in sensor_ids:
        if key in cache:
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

    # La FPPT-T2400 con PV leggero / carico minimo invia spesso 0 minuti anche se
    # la batteria è al 50%: non è un tempo reale, è "non calcolabile".
    if abs(power) < 30.0 and outp < 30.0 and inp < 30.0:
        decoded.pop("remaining_time_minutes", None)
        return

    # Se invece c'è potenza reale ma la LAN manda 0, lascia che il fallback stimato
    # ricalcoli il tempo dopo l'update del cache.

def apply_battery_remaining_time_estimate(cache, args, decoded=None):
    capacity = float(getattr(args, "battery_capacity_wh", 0) or 0)
    if capacity <= 0:
        return set()
    estimate_allowed = "remaining_time_minutes" not in cache
    decoded_minutes = None
    if decoded is not None and "remaining_time_minutes" in decoded:
        try:
            decoded_minutes = int(float(decoded["remaining_time_minutes"] or 0))
            estimate_allowed = decoded_minutes == 0
        except (TypeError, ValueError):
            estimate_allowed = False
    try:
        soc = float(cache["battery_percentage"])
        power = float(cache["battery_total_power"])
    except (KeyError, TypeError, ValueError):
        return set()
    if not 0 <= soc <= 100:
        return set()

    min_power_w = 20.0
    if abs(power) < min_power_w:
        return set()

    if power > 0:
        target_wh = capacity * max(0.0, 100.0 - soc) / 100.0
    else:
        target_wh = capacity * soc / 100.0
        usable_ratio = float(getattr(args, "battery_discharge_usable_ratio", 0.88) or 0.88)
        usable_ratio = max(0.5, min(1.0, usable_ratio))
        target_wh *= usable_ratio

    if target_wh <= 0:
        minutes = 0
    else:
        minutes = max(1, int(round(target_wh / abs(power) * 60.0)))
    if minutes > 100000:
        return set()

    if decoded_minutes is not None and decoded_minutes > 0:
        max_reasonable_minutes = max(1440, minutes * 4)
        if decoded_minutes <= max_reasonable_minutes:
            return set()
        cache["remaining_time_minutes"] = minutes
        return {"remaining_time_minutes"}

    if not estimate_allowed:
        return set()

    # evita salti 0h <-> valore stimato quando la LAN restituisce 0
    prev = cache.get("remaining_time_minutes")
    if minutes <= 0 and prev:
        minutes = prev
    if prev == minutes:
        return set()
    cache["remaining_time_minutes"] = minutes
    return {"remaining_time_minutes"}


def apply_battery_soc_tracking(cache, decoded, args):
    capacity = float(getattr(args, "battery_capacity_wh", 0) or 0)
    if capacity <= 0 or not getattr(args, "battery_soc_estimate", False):
        return set()
    now = time.time()
    if "battery_percentage" in decoded:
        try:
            soc = float(decoded["battery_percentage"])
        except (TypeError, ValueError):
            return set()
        if 0 <= soc <= 100:
            cache["_battery_soc_estimate_wh"] = capacity * soc / 100.0
            cache["_battery_soc_estimate_ts"] = now
        return set()
    if "_battery_soc_estimate_wh" not in cache or "battery_total_power" not in cache:
        return set()
    try:
        wh = float(cache["_battery_soc_estimate_wh"])
        last_ts = float(cache["_battery_soc_estimate_ts"])
        power = float(cache["battery_total_power"])
    except (TypeError, ValueError):
        return set()
    dt = now - last_ts
    if dt <= 0 or dt > 300:
        cache["_battery_soc_estimate_ts"] = now
        return set()
    changed = set()
    wh = max(0.0, min(capacity, wh + power * dt / 3600.0))
    cache["_battery_soc_estimate_wh"] = wh
    cache["_battery_soc_estimate_ts"] = now
    soc = round(100.0 * wh / capacity, 1)
    soc = int(soc) if float(soc).is_integer() else soc
    if cache.get("battery_percentage") != soc:
        cache["battery_percentage"] = soc
        changed.add("battery_percentage")
    remaining_wh = int(round(wh))
    if cache.get("battery_remaining_wh") != remaining_wh:
        cache["battery_remaining_wh"] = remaining_wh
        changed.add("battery_remaining_wh")
    return changed


def apply_device_status_correction(cache, decoded):
    """Deriva lo stato reale usando potenze correnti oltre al codice firmware."""
    if "device_status_raw" not in decoded:
        return set()
    status_raw = decoded["device_status_raw"]
    now = time.time()

    if status_raw == 4:
        cache.pop("_status_grid_seen_ts", None)
        new_label = "Bypass"
        if cache.get("device_status") != new_label:
            cache["device_status"] = new_label
            return {"device_status"}
        return set()

    def _num(key):
        try:
            return float(cache.get(key) if key in cache else decoded.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    battery_power = _num("battery_total_power")
    grid_power = _num("grid_b_power")
    ac_output_power = _num("ac_output_power")
    dc_output_power = _num("dc_output_power")
    output_power = max(grid_power, ac_output_power, dc_output_power)
    input_power = max(_num("pv_input_power"), _num("ac_input_power"))

    # Evita rimbalzi Standby/In carica/In scarica causati da rumore intorno a 0 W.
    # L'app ufficiale resta in Standby con PV 5-10 W e batteria +/-10 W.
    status_deadband_w = 30.0
    active_power_w = 30.0
    pv_active_w = 5.0
    standby_drain_w = 60.0
    standby_pv_w = 15.0

    if output_power > active_power_w:
        cache["_status_grid_seen_ts"] = now

    last_seen = float(cache.get("_status_grid_seen_ts") or 0)
    output_recent = (now - last_seen) < 120

    if battery_power > status_deadband_w and output_power > active_power_w:
        new_label = "Carica e scarica"
    elif input_power > pv_active_w and output_power > active_power_w:
        new_label = "Carica e scarica"
    elif output_power < active_power_w and input_power < standby_pv_w and abs(battery_power) < standby_drain_w:
        new_label = "Standby"
    elif abs(battery_power) < status_deadband_w and output_power < active_power_w and input_power < active_power_w:
        new_label = "Standby"
    elif battery_power < -status_deadband_w:
        new_label = "In scarica"
    elif battery_power > status_deadband_w and (output_power > active_power_w or output_recent):
        new_label = "Carica e scarica"
    elif battery_power > status_deadband_w or input_power > active_power_w:
        if output_power > active_power_w:
            new_label = "Carica e scarica" if input_power + status_deadband_w >= output_power else "In scarica"
        else:
            new_label = "In carica"
    elif output_power > active_power_w:
        new_label = "In scarica"
    elif status_raw == 2:
        new_label = "In scarica"
    elif status_raw == 3:
        new_label = "Carica e scarica"
    else:
        new_label = DEVICE_STATUS_LABELS.get(status_raw, f"Stato {status_raw}")

    if cache.get("device_status") != new_label:
        cache["device_status"] = new_label
        return {"device_status"}
    return set()


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


def words16(data):
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2)]


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


def publish_reported_command_states(mqtt, base_topic, reported):
    for command_id, value in reported.items():
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", value, retain=True)
    save_switch_cache(reported)


def publish_output_power_state(mqtt, base_topic, watts, source="LAN"):
    try:
        watts = int(float(watts))
    except (TypeError, ValueError):
        return
    if not 100 <= watts <= 800:
        return
    mqtt.publish(f"{base_topic}/cmd_state/output_power", str(watts), retain=True)
    _dprint(f"{source} output_power_set={watts}W", flush=True)


def _initial_command_states_from_env() -> dict:
    raw = os.environ.get("WF_SWITCH_STATES", "").strip()
    if not raw:
        return {}
    states = {}
    valid = set(SWITCH_HEX) | {"mode", "output_power"}
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in valid and value:
            states[key] = value
    return states


def publish_initial_command_states(mqtt, base_topic):
    initial = _initial_command_states_from_env()
    for switch_id in SWITCH_HEX:
        mqtt.publish(f"{base_topic}/cmd_state/{switch_id}", initial.get(switch_id, b""), retain=True)
    mqtt.publish(f"{base_topic}/cmd_state/mode", initial.get("mode", b""), retain=True)
    mqtt.publish(f"{base_topic}/cmd_state/output_power", initial.get("output_power", b""), retain=True)
    if initial:
        save_switch_cache({k: v for k, v in initial.items() if k != "output_power"})


def publish_inferred_command_states(mqtt, base_topic, cache, decoded):
    inferred = {}

    def _num(key):
        try:
            return float(cache.get(key) if key in cache else decoded.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    # Segue le modifiche fatte dall'app usando solo prove fisiche dai sensori LAN.
    # Evita la vecchia scansione generica dei frame, che poteva creare switch falsi.
    if any(k in decoded for k in ("grid_voltage", "grid_b_power", "ac_output_power")):
        grid_power = max(abs(_num("grid_b_power")), abs(_num("ac_output_power")))
        if grid_power >= 5:
            inferred["grid"] = "ON"
        elif _num("grid_voltage") <= 1 and grid_power < 1:
            inferred["grid"] = "OFF"

    if any(k in decoded for k in (
        "dc_output_power",
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
        inferred["dc"] = "ON" if dc_voltage > 1 or _num("dc_output_power") > 1 else "OFF"

    if inferred:
        publish_reported_command_states(mqtt, base_topic, inferred)
        _dprint(f"inferred command states from sensors: {inferred}", flush=True)


def apply_reported_sensor_overrides(cache, reported):
    changed = set()

    def set_zero(key):
        if cache.get(key) != 0:
            changed.add(key)
        cache[key] = 0

    if reported.get("grid") == "OFF":
        for key in ("grid_voltage", "grid_freq", "grid_b_power", "ac_input_power", "ac_output_power"):
            set_zero(key)
    if reported.get("dc") == "OFF":
        for key in DC_OUTPUT_SENSOR_KEYS:
            set_zero(key)
    if changed:
        apply_derived_sensors(cache)
        changed.update(("total_input_power", "total_output_power"))
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


def handle_mqtt_command(topic, payload, device_sock, mqtt, base_topic, key, iv, args):
    prefix = f"{base_topic}/set/"
    if not topic.startswith(prefix):
        return
    command_id = topic[len(prefix):]
    payload = payload.strip()
    if not payload:
        return

    if command_id in SWITCH_HEX:
        state = payload.upper()
        if state not in ("ON", "OFF"):
            return
        if command_id == "grid":
            last_state = getattr(args, "_last_grid_command_state", None)
            last_ts = float(getattr(args, "_last_grid_command_ts", 0) or 0)
            if last_state and last_state != state and time.time() - last_ts < 2.0:
                print(f"ignored rapid opposite grid command: {last_state} -> {state}", flush=True)
                return
            args._last_grid_command_state = state
            args._last_grid_command_ts = time.time()
        frame = _build_write_frame(SWITCH_HEX[command_id][state.lower()], key, iv, args)
        _send_frame(device_sock, args, frame)
        mqtt.publish(f"{base_topic}/cmd_state/{command_id}", state, retain=True)
        _dprint(f"sent {command_id} {state}", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60   # 60s grace dopo switch
        return

    if command_id == "mode":
        if payload not in MODE_HEX_BY_LABEL:
            return
        frame = _build_write_frame(MODE_HEX_BY_LABEL[payload], key, iv, args)
        _send_frame(device_sock, args, frame)
        if payload == "Micro-Inverter":
            _send_frame(device_sock, args, _build_write_frame(SWITCH_HEX["grid"]["on"], key, iv, args))
            mqtt.publish(f"{base_topic}/cmd_state/grid", "ON", retain=True)
        else:
            _send_frame(device_sock, args, _build_write_frame(SWITCH_HEX["grid"]["off"], key, iv, args))
            mqtt.publish(f"{base_topic}/cmd_state/grid", "OFF", retain=True)
        mqtt.publish(f"{base_topic}/cmd_state/mode", payload, retain=True)
        _dprint(f"sent mode {payload}", flush=True)
        args._next_bus_kick = time.time() + 2.0
        args._cmd_grace_until = time.time() + 60   # 60s grace dopo cambio modalità
        return

    if command_id == "output_power":
        try:
            watts = _normalize_output_power(payload, args)
        except ValueError:
            return
        args._pending_output_power = watts
        args._pending_output_power_due = time.time() + float(getattr(args, "output_power_debounce", 0.25) or 0.25)
        args._next_bus_kick = time.time() + 2.5
        _dprint(f"queued output_power {watts}W", flush=True)


def _flush_pending_output_power(device_sock, mqtt, base_topic, key, iv, args):
    watts = getattr(args, "_pending_output_power", None)
    due = getattr(args, "_pending_output_power_due", 0)
    if watts is None or time.time() < due:
        return
    frame = _build_output_power_frame(watts, key, iv, args)
    _send_frame(device_sock, args, frame)
    mqtt.publish(f"{base_topic}/cmd_state/output_power", str(watts), retain=True)
    print(f"sent output_power {watts}W", flush=True)
    args._pending_output_power = None
    args._pending_output_power_due = 0
    # Il device può bloccare il reporting per 60-120s mentre applica il nuovo
    # limite di potenza (reset interno inverter). Impostiamo una grace period
    # così non riconnettimamo (e non triggeriamo automazioni HA) durante questo periodo.
    args._cmd_grace_until = time.time() + 120


# ══════════════════════════════════════════════════════════════════════════════
# LAN key refresh
# ══════════════════════════════════════════════════════════════════════════════

def _refresh_lan_key(args) -> bool:
    try:
        from wf_autodiscovery import setup as _setup
        _setup(force=True)
        new_hex = os.environ.get("LAN_KEY_HEX", "").strip()
        if new_hex:
            new_key = base64.b64encode(bytes.fromhex(new_hex)).decode("ascii")
            if new_key != args.key:
                args.key = new_key
                print("LAN key refreshed from cloud", flush=True)
                return True
        return False
    except Exception as exc:
        print(f"LAN key refresh failed: {exc}", flush=True)
        return False


def _cloud_switch_states() -> dict:
    try:
        import requests as _req
    except ImportError:
        return {}
    token        = os.environ.get("WF_TOKEN", "")
    realtime_url = os.environ.get("REALTIME_ATTRS_URL", "")
    device_key   = os.environ.get("DEVICE_KEY", "")
    product_key  = os.environ.get("PRODUCT_KEY", "")
    if not all((token, realtime_url, device_key, product_key)):
        return {}
    ATTR_MAP = {
        "beepSwitch": "beep", "beep": "beep", "buzzer": "beep",
        "gridSwitch": "grid", "grid": "grid", "gridOutput": "grid", "gridOutputSwitch": "grid",
        "acSwitch": "ac", "ac": "ac", "acOutput": "ac", "acOutputSwitch": "ac",
        "dcSwitch": "dc", "dc": "dc", "dcOutput": "dc", "dcOutputSwitch": "dc",
        "ledSwitch": "led", "led": "led", "lightSwitch": "led",
        "screenSwitch": "screen", "screen": "screen", "displaySwitch": "screen",
        "slowReporting": "slow_reporting", "slowReport": "slow_reporting",
    }
    try:
        auth = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        headers = {"Authorization": auth, "Content-Type": "application/json"}
        j = None
        for params in (
            {"dk": device_key, "pk": product_key},
            {"deviceKey": device_key, "productKey": product_key},
        ):
            r = _req.get(realtime_url, params=params, headers=headers, timeout=10)
            candidate = r.json()
            if candidate.get("code") == 200:
                j = candidate
                break
        if j is None:
            return {}
        attrs = j.get("data") or {}
        if isinstance(attrs, list):
            attrs = {item.get("id", ""): item.get("val", "") for item in attrs if isinstance(item, dict)}
        states = {}
        for cloud_key, switch_id in ATTR_MAP.items():
            if cloud_key in attrs and switch_id not in states:
                val = str(attrs[cloud_key]).upper()
                if val in ("1", "TRUE", "ON"):
                    states[switch_id] = "ON"
                elif val in ("0", "FALSE", "OFF"):
                    states[switch_id] = "OFF"
        return states
    except Exception as exc:
        _dprint(f"cloud switch states error: {exc}", flush=True)
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# WiFi freeze recovery
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════

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
    print(f"MQTT connected; publishing discovery...", flush=True)
    publish_discovery(mqtt, args.topic, args)
    subscribe_command_topics(mqtt, args.topic)

    publish_initial_command_states(mqtt, args.topic)
    clear_retained_sensor_states(mqtt, args.topic)
    cleanup_disabled_cache_files(args)

    sensor_cache: dict = {}

    reconnect_delay = RECONNECT_DELAY_INIT
    unreachable_since: float | None = None
    broken_pipe_since: float | None = None
    lan_disconnected_since: float | None = None
    availability_offline_sent = False
    sensor_silence_streak = 0       # riconnessioni consecutive senza dati sensori
    sensor_silence_since: float | None = None
    session_had_sensor_data = False  # questa sessione TCP ha ricevuto almeno un dato
    last_wifi_frozen_alert = 0.0
    last_full_bus_mask = 0.0

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
                # broken_pipe_since NON viene resettato qui: il TCP connect può
                # riuscire e poi dare subito Broken pipe (firmware non pronto).
                # Viene resettato solo quando arrivano dati sensori reali.
                reconnect_delay = RECONNECT_DELAY_INIT
                lan_disconnected_since = None
                availability_offline_sent = False
                session_had_sensor_data = False
                # Reset stato pendente dalla sessione precedente (Bug 2 fix):
                # evita comandi indesiderati su device appena riconnesso
                args._grid_fault_recovery   = False
                args._grid_retrigger_on_due = 0
                args._pending_output_power  = None
                args._pending_output_power_due = 0
                args._next_bus_kick         = 0
                args._fault_recovery_count  = 0  # contatore retrigger E02 per sessione
                args._cmd_grace_until       = 0  # reset grace period su riconnessione

                mqtt.publish(availability_topic, "online", retain=True)
                print(f"LAN connected; MQTT at {args.mqtt_host}:{args.mqtt_port}", flush=True)

                args._lan_packet_id = 1
                time.sleep(1.0)  # grace period post-login prima dei comandi
                send_report_subscription(sock, key, iv, args)
                if FULL_BUS_MASK_COOLDOWN <= 0 or time.time() - last_full_bus_mask >= FULL_BUS_MASK_COOLDOWN:
                    send_bus_mask(sock, key, iv, args)
                    last_full_bus_mask = time.time()
                else:
                    # IMPORTANTISSIMO:
                    # non sostituire la full mask con BATTERY_MASK_IDS(2) al reconnect.
                    # Nei log reali questa sequenza ripetuta "ids=2" porta a sessioni mute
                    # e impedisce il recupero stabile dei report LAN. Durante il cooldown
                    # manteniamo solo subscription + refresh: basta per riagganciare lo stream
                    # senza restringere la mask attiva del device.
                    print("skipped full bus_mask: cooldown active; keeping previous report mask", flush=True)
                send_bus_refresh(sock, key, iv, args)          # modalità alta frequenza

                # ── Drain comandi MQTT stantii ────────────────────────────────
                # Il broker MQTT mantiene la connessione attiva durante i disconnect
                # LAN: i comandi inviati dall'utente in HA si accumulano nel buffer
                # rx e verrebbero eseguiti tutti in sequenza appena il device torna
                # online, causando comportamenti caotici (grid ON→OFF→ON→OFF).
                # Scartiamo per ~1s qualsiasi comando accodato durante il disconnect.
                _drain_end = time.time() + 1.0
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
                next_bus_refresh  = now + BUS_REFRESH_INTERVAL if BUS_REFRESH_INTERVAL > 0 else 0
                startup_primer_subscribe_sent = False
                startup_primer_mask_sent = False
                sensor_soft_subscribe_sent = False
                sensor_soft_refresh_sent = False
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
                    if (
                        not session_had_sensor_data
                        and sensor_silence >= STARTUP_PRIMER_SUBSCRIBE_AFTER
                        and not startup_primer_subscribe_sent
                        and now >= _grace_until
                    ):
                        print(
                            f"startup no sensor data for {sensor_silence:.0f}s — primer report subscription",
                            flush=True,
                        )
                        send_report_subscription(sock, key, iv, args)
                        startup_primer_subscribe_sent = True
                    elif (
                        not session_had_sensor_data
                        and sensor_silence >= STARTUP_PRIMER_MASK_AFTER
                        and not startup_primer_mask_sent
                        and now >= _grace_until
                    ):
                        print(
                            f"startup no sensor data for {sensor_silence:.0f}s — primer refresh",
                            flush=True,
                        )
                        # Sessione muta: forziamo refresh + full mask, non ids=2.
                        # Il log reale 0.3.74 mostra che solo il refresh non sblocca
                        # sempre la powerstation quando la sessione nasce senza sensori.
                        send_bus_refresh(sock, key, iv, args)
                        send_bus_mask(sock, key, iv, args)
                        next_bus_mask = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0
                        startup_primer_mask_sent = True

                    if sensor_silence >= SENSOR_RECONNECT_AFTER and now >= _grace_until:
                        raise RuntimeError(
                            f"no sensor data for {now - last_sensor_rx:.0f}s — reconnecting"
                        )

                    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                        _send_frame(sock, args, encode_cmd(28727, _next_packet_id(args)))
                        last_heartbeat = now

                    if now - last_mqtt_ping >= MQTT_PING_INTERVAL:
                        mqtt.ping()
                        last_mqtt_ping = now

                    # Rinnova subscription: il device la dimentica se resta senza richiami.
                    # Anche durante il silenzio sensori continuiamo, come nel bridge 0.3.55:
                    # se blocchiamo questi richiami, la LAN resta ferma fino al recovery.
                    if REPORT_RESUBSCRIBE > 0 and now >= next_resubscribe:
                        send_report_subscription(sock, key, iv, args)
                        next_resubscribe = now + REPORT_RESUBSCRIBE

                    # Logica veloce 0.2.7: richiedi sempre la mask completa e poi
                    # risveglia il bus. Niente ids=2: full mask = tutti i sensori.
                    if BUS_MASK_INTERVAL > 0 and now >= next_bus_mask:
                        send_bus_mask(sock, key, iv, args)
                        send_bus_refresh(sock, key, iv, args)
                        next_bus_mask = now + BUS_MASK_INTERVAL

                    # Refresh standalone, molto meno importante del full bus_mask.
                    if BUS_REFRESH_INTERVAL > 0 and now >= next_bus_refresh:
                        send_bus_refresh(sock, key, iv, args)
                        next_bus_refresh = now + BUS_REFRESH_INTERVAL

                    for topic, payload, retained in mqtt.read_messages():
                        if retained:
                            _dprint(f"ignored retained MQTT command: {topic}={payload}", flush=True)
                            continue
                        if not session_had_sensor_data:
                            print(f"command dropped (no sensor data yet): {topic}={payload}", flush=True)
                            continue
                        handle_mqtt_command(topic, payload, sock, mqtt, args.topic, key, iv, args)

                    if session_had_sensor_data:   # Bug 3 fix
                        _flush_pending_output_power(sock, mqtt, args.topic, key, iv, args)

                    # ── Grid retrigger after fault recovery ───────────────────
                    if getattr(args, "_grid_fault_recovery", False):
                        args._grid_fault_recovery = False
                        frame = _build_write_frame(SWITCH_HEX["grid"]["off"], key, iv, args)
                        _send_frame(sock, args, frame)
                        mqtt.publish(f"{args.topic}/cmd_state/grid", "OFF", retain=True)
                        print("grid OFF (fault recovery — retrigger)", flush=True)
                        args._grid_retrigger_on_due = time.time() + 2.0

                    retrigger_due = getattr(args, "_grid_retrigger_on_due", 0) or 0
                    if retrigger_due and now >= retrigger_due:
                        args._grid_retrigger_on_due = 0
                        frame = _build_write_frame(SWITCH_HEX["grid"]["on"], key, iv, args)
                        _send_frame(sock, args, frame)
                        mqtt.publish(f"{args.topic}/cmd_state/grid", "ON", retain=True)
                        print("grid ON (fault recovery — retrigger)", flush=True)
                        args._next_bus_kick = time.time() + 2.0

                    kick_due = getattr(args, "_next_bus_kick", 0) or 0
                    if kick_due and now >= kick_due:
                        # Dopo ogni comando: bus_refresh + bus_mask completa (ids=31).
                        # Mantiene tutti i sensori attivi senza restringere la mask a batteria/base.
                        send_bus_refresh(sock, key, iv, args)
                        send_bus_mask(sock, key, iv, args)
                        args._next_bus_kick = 0
                        next_bus_mask = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0
                        next_bus_refresh  = now + BUS_REFRESH_INTERVAL if BUS_REFRESH_INTERVAL > 0 else 0

                    # ── Receive and decode LAN frames ────────────────────────
                    data = recv_some(sock, 0.2)
                    if data:
                        last_frame_rx = time.time()
                        recv_buf += data

                    if not recv_buf:
                        continue

                    frames = list(iter_frames(recv_buf))
                    if frames:
                        last_aa = recv_buf.rfind(b"\xaa\xaa")
                        recv_buf = recv_buf[last_aa:] if last_aa > 0 else b""
                    elif len(recv_buf) > 8192:
                        print(f"LAN recv buffer discarded ({len(recv_buf)} bytes without frame)", flush=True)
                        recv_buf = b""

                    for frame in frames:
                        raw_payload = frame["payload"]
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
                            )

                        decoded = decode_bus_payload(plain)
                        if decoded:
                            if not args.show_firmware_sensors:
                                decoded = {k: v for k, v in decoded.items() if k not in FIRMWARE_SENSOR_IDS}
                            if any(k in SENSOR_DEFS for k in decoded):
                                last_sensor_rx = time.time()
                                sensor_soft_subscribe_sent = False
                                sensor_soft_refresh_sent = False
                                sensor_silence_since = None
                                sensor_silence_streak = 0
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

                            zero_values = zero_sensor_values_for_frame(sensor_cache, decoded)
                            if zero_values:
                                decoded.update(zero_values)
                            suppress_transient_ac_zeros(sensor_cache, decoded, args)

                            # ── Auto-recovery: E02 cleared in Micro-Inverter mode ────────────
                            # SOLO per E02: spina non inserita → micro-inverter attivato.
                            # Quando la spina viene attaccata l'E02 torna Normale ma il
                            # micro-inverter non riparte: serve grid OFF → grid ON per sbloccare.
                            # ATTENZIONE: NON attivare per altri fault (es. E40, E01…):
                            # il retrigger peggiorerebbe un fault già attivo causando un loop.
                            if "fault_code" in decoded:
                                prev_fault = sensor_cache.get("fault_code")
                                curr_fault = decoded["fault_code"]
                                if (prev_fault == "Errore E02"   # solo E02, non altri fault
                                        and curr_fault == "Normale"):
                                    sw = load_switch_cache()
                                    if sw.get("mode") == "Micro-Inverter" and sw.get("grid") == "ON":
                                        count = int(getattr(args, "_fault_recovery_count", 0) or 0)
                                        if count < FAULT_RECOVERY_MAX:
                                            args._fault_recovery_count = count + 1
                                            print(
                                                f"E02 cleared → Normale in Micro-Inverter — "
                                                f"grid retrigger programmato "
                                                f"({args._fault_recovery_count}/{FAULT_RECOVERY_MAX})",
                                                flush=True,
                                            )
                                            args._grid_fault_recovery = True
                                        else:
                                            print(
                                                f"E02 cleared ma max retrigger raggiunto "
                                                f"({FAULT_RECOVERY_MAX}) — skip, riavvio manuale necessario",
                                                flush=True,
                                            )

                            guard_zero_remaining_time(decoded, sensor_cache)
                            sensor_cache.update(decoded)
                            publish_keys = set(decoded)
                            apply_derived_sensors(sensor_cache)
                            publish_keys.update(apply_battery_capacity_sensors(sensor_cache, decoded, args))
                            publish_keys.update(apply_grid_frequency_default(sensor_cache, decoded, args))
                            if any(k in decoded for k in ("pv_input_power", "ac_input_power")):
                                publish_keys.add("total_input_power")
                            if any(k in decoded for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
                                publish_keys.add("total_output_power")
                            publish_keys.update(apply_battery_power_balance(sensor_cache, decoded, args))
                            publish_keys.update(apply_device_status_correction(sensor_cache, decoded))
                            publish_keys.update(apply_battery_soc_tracking(sensor_cache, decoded, args))
                            publish_keys.update(apply_battery_remaining_time_estimate(sensor_cache, args, decoded))
                            save_battery_cache(sensor_cache, decoded, args)
                            sensor_cache["updated_at"] = int(time.time())
                            publish_sensor_cache(mqtt, args.topic, sensor_cache, publish_keys)
                            if "output_power_set" in decoded:
                                publish_output_power_state(mqtt, args.topic, decoded["output_power_set"], "LAN decoded")
                            publish_inferred_command_states(mqtt, args.topic, sensor_cache, decoded)
                            if decoded:
                                debug_decoded = dict(decoded)
                                if "device_status_raw" in debug_decoded:
                                    debug_decoded["device_status_corrected"] = sensor_cache.get("device_status")
                                _dprint(f"decoded: {debug_decoded}", flush=True)

                        reported = extract_reported_command_states(plain) if len(plain) <= 96 else {}
                        if reported:
                            if "output_power" in reported:
                                publish_output_power_state(mqtt, args.topic, reported["output_power"], "LAN reported")
                            publish_reported_command_states(mqtt, args.topic, reported)
                            override_keys = apply_reported_sensor_overrides(sensor_cache, reported)
                            if override_keys:
                                sensor_cache["updated_at"] = int(time.time())
                                publish_sensor_cache(mqtt, args.topic, sensor_cache, override_keys)

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
                is_sensor_silence = "no sensor data" in exc_text
                if is_sensor_silence:
                    # BUGFIX 0.3.52:
                    # prima lo streak veniva incrementato SOLO se la sessione aveva già
                    # ricevuto sensori. Quando invece il reconnect creava sessioni mute,
                    # "wifi_frozen" non partiva mai. Ora contiamo entrambe le condizioni.
                    if sensor_silence_since is None:
                        sensor_silence_since = now
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
                        alert_elapsed = now - last_wifi_frozen_alert
                        if last_wifi_frozen_alert and alert_elapsed < WIFI_FROZEN_ALERT_COOLDOWN:
                            print(
                                f"MQTT wifi_frozen alert soppresso "
                                f"(cooldown {WIFI_FROZEN_ALERT_COOLDOWN - alert_elapsed:.0f}s)",
                                flush=True,
                            )
                        else:
                            try:
                                mqtt.publish(
                                    f"{args.topic}/event/wifi_frozen",
                                    json.dumps({
                                        "streak": sensor_silence_streak,
                                        "ts": int(now),
                                        "message": (
                                            f"PowerStation WiFi reporting frozen "
                                            f"({sensor_silence_streak} reconnects senza dati). "
                                            "Riavviare il WiFi del router o la powerstation."
                                        ),
                                    }),
                                    retain=False,
                                )
                                print(
                                    f"MQTT wifi_frozen alert pubblicato (streak={sensor_silence_streak})",
                                    flush=True,
                                )
                                last_wifi_frozen_alert = now
                            except Exception as me:
                                print(f"MQTT wifi_frozen publish failed: {me}", flush=True)
                    if now - sensor_silence_since >= SENSOR_SILENCE_RESTART:
                        print(
                            f"Sensori assenti da {now - sensor_silence_since:.0f}s — availability offline e riavvio bridge",
                            flush=True,
                        )
                        try:
                            mqtt.publish(availability_topic, "offline", retain=True)
                            availability_offline_sent = True
                        except Exception:
                            pass
                        try:
                            mqtt.disconnect()
                        except Exception:
                            pass
                        os.execv(sys.executable, [sys.executable] + sys.argv)
                else:
                    # Errore diverso (broken pipe, host unreachable…) → streak azzerata
                    if sensor_silence_streak > 0:
                        print(f"WiFi freeze streak reset (era {sensor_silence_streak})", flush=True)
                    sensor_silence_streak = 0
                    sensor_silence_since = None

                if "mqtt disconnected" in exc_text:
                    print("MQTT disconnected - restarting bridge", flush=True)
                    os.execv(sys.executable, [sys.executable] + sys.argv)

                # Detect hard unreachability (WiFi/network down, not just device)
                exc_errno = getattr(exc, "errno", None)
                is_hard_unreachable = (
                    exc_errno in {errno.EHOSTUNREACH, errno.ENETUNREACH} or
                    any(s in exc_text for s in ("host is unreachable", "network is unreachable", "no route to host"))
                )
                if is_hard_unreachable:
                    if unreachable_since is None:
                        unreachable_since = now
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

                # Restart the process if the network has been hard-unreachable too long
                # (handles the case where the WiFi router takes >3 min to come back)
                if unreachable_since is not None and now - unreachable_since >= UNREACHABLE_RESTART:
                    print(f"LAN unreachable for {now - unreachable_since:.0f}s — restarting bridge", flush=True)
                    try:
                        mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                    except Exception:
                        pass
                    os.execv(sys.executable, [sys.executable] + sys.argv)

                # Restart the process if stuck in a broken-pipe loop
                # (device firmware accepts TCP but drops connection after login;
                #  a fresh process start breaks the cycle, same as manual restart)
                if broken_pipe_since is not None and now - broken_pipe_since >= BROKEN_PIPE_RESTART:
                    print(f"Broken-pipe loop for {now - broken_pipe_since:.0f}s — restarting bridge", flush=True)
                    try:
                        mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                    except Exception:
                        pass
                    os.execv(sys.executable, [sys.executable] + sys.argv)

                # Refresh LAN key on auth failure (unbind/rebind dall'app)
                if "login failed" in exc_text:
                    print("Login failed — refreshing LAN key from cloud", flush=True)
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
                        and not is_broken_pipe and not is_sensor_silence:
                    try:
                        mqtt.publish(availability_topic, "offline", retain=True)
                        availability_offline_sent = True
                        print(f"MQTT availability → offline after {elapsed:.0f}s outage", flush=True)
                    except Exception:
                        pass

                # Wait, checking offline trigger every second during the delay
                sleep_until = time.time() + reconnect_delay
                while time.time() < sleep_until:
                    if not availability_offline_sent and lan_disconnected_since is not None \
                            and not is_broken_pipe and not is_sensor_silence:
                        if time.time() - lan_disconnected_since >= AVAILABILITY_HOLD:
                            try:
                                mqtt.publish(availability_topic, "offline", retain=True)
                                availability_offline_sent = True
                            except Exception:
                                pass
                    time.sleep(min(1.0, max(0.0, sleep_until - time.time())))

                reconnect_delay = min(reconnect_delay * 1.5, RECONNECT_DELAY_MAX)

    finally:
        try:
            mqtt.publish(availability_topic, "offline", retain=True)
        except Exception:
            pass
        try:
            mqtt.disconnect()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Landbook FPPT-T2400 LAN -> HA MQTT bridge")
    parser.add_argument("--device-host", default="192.168.1.65")
    parser.add_argument("--device-port", type=int, default=6607)
    parser.add_argument("--key", default=DEFAULT_KEY)
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
    parser.add_argument("--battery-discharge-usable-ratio", type=float, default=0.88)
    parser.add_argument("--battery-current-fallback-voltage", type=float, default=52.8)
    parser.add_argument("--battery-soc-estimate", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--grid-frequency-default", type=float, default=50)
    parser.add_argument("--ac-zero-hold-seconds", type=float, default=18)
    parser.add_argument("--sensor-expire-after", type=int, default=0)
    parser.add_argument("--battery-info-expire-after", type=int, default=86400)
    parser.add_argument("--show-firmware-sensors", action="store_true", default=False)
    parser.add_argument("--output-power-min", type=int, default=100)
    parser.add_argument("--output-power-max", type=int, default=800)
    parser.add_argument("--output-power-step", type=int, default=10)
    parser.add_argument("--output-power-debounce", type=float, default=0.25)
    parser.add_argument("--device-tx-min-interval", type=float, default=0.6)
    args = parser.parse_args()
    print(f"Landbook LAN MQTT Bridge {APP_VERSION} starting", flush=True)
    run(args)


if __name__ == "__main__":
    main()
