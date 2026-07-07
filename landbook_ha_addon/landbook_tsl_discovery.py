"""TSL-driven Home Assistant discovery catalogs.

Reads the TSL dump produced by wf_autodiscovery and yields the catalogs the
bridge needs to (a) build MQTT discovery payloads for switches/sensors and
(b) translate command codes to TTLV ids+types when publishing commands.

All shape inference comes from the TSL itself — no hardcoded per-model tables.
The only constants here are HA unit→device_class mappings, which are protocol-
agnostic.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("tsl_discovery")

TSL_DUMP_PATH = "/data/landbook_tsl.json"


# ── Unit / type → Home Assistant device_class & state_class ────────────────

# Aliyun TSLs report units as plain strings ("V", "%", "kWh", "°C", "Hz"…).
# We translate them once here; everything else flows from the TSL.
UNIT_TO_DEVICE_CLASS = {
    "V":   ("voltage",            "measurement"),
    "mV":  ("voltage",            "measurement"),
    "A":   ("current",            "measurement"),
    "mA":  ("current",            "measurement"),
    "W":   ("power",              "measurement"),
    "kW":  ("power",              "measurement"),
    "Wh":  ("energy",             "total_increasing"),
    "kWh": ("energy",             "total_increasing"),
    "Hz":  ("frequency",          "measurement"),
    "°C":  ("temperature",        "measurement"),
    "℃":  ("temperature",        "measurement"),
    "C":   ("temperature",        "measurement"),
    "%":   (None,                 "measurement"),    # may be battery, may not
    "min": ("duration",           "measurement"),
    "s":   ("duration",           "measurement"),
    "h":   ("duration",           "measurement"),
    "Ah":  (None,                 "measurement"),
    "VA":  ("apparent_power",     "measurement"),
}

# Some TSL units are written as raw enums (e.g. "Watt"); normalize before lookup.
UNIT_ALIASES = {
    "Watt": "W", "Volt": "V", "Ampere": "A", "Hertz": "Hz",
    "Celsius": "°C", "celsius": "°C", "degC": "°C", "℃": "°C",
    "percent": "%", "Percent": "%", "Percentage": "%",
    "Minutes": "min", "Minute": "min", "minutes": "min", "minute": "min",
    "kW.h": "kWh", "KW.h": "kWh", "kW·h": "kWh", "kw.h": "kWh",
}


def _device_class(unit: Optional[str], code: str) -> Tuple[Optional[str], Optional[str]]:
    if not unit:
        return None, "measurement"
    u = UNIT_ALIASES.get(unit, unit).strip()
    dc, sc = UNIT_TO_DEVICE_CLASS.get(u, (None, "measurement"))
    lc = str(code).lower()
    # battery_percentage → battery device_class even though unit is %
    if u == "%" and ("battery" in lc or "soc" in lc):
        return "battery", "measurement"
    # Remaining capacity is an instantaneous energy value, not an increasing total.
    # HA rejects state_class=measurement with device_class=energy.
    if u in ("Wh", "kWh") and "remaining" in lc:
        return dc, None
    return dc, sc


def _unit_string(specs: Any) -> Optional[str]:
    """Aliyun puts unit in specs.unit / unitName / unitDesc; sometimes inside dataType."""
    if isinstance(specs, dict):
        for key in ("unit", "unitName", "unitDesc", "displayUnit", "symbol"):
            v = specs.get(key)
            if v:
                raw = str(v).strip()
                return UNIT_ALIASES.get(raw, raw)
    return None


def _step(specs: Any) -> float:
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


def _range(specs: Any) -> Tuple[Optional[float], Optional[float]]:
    if not isinstance(specs, dict):
        return None, None
    def _f(*keys):
        for k in keys:
            v = specs.get(k)
            if v is None:
                continue
            try:
                return float(v)
            except (TypeError, ValueError):
                pass
        return None
    return _f("min", "minValue", "minimum"), _f("max", "maxValue", "maximum")


def _enum_options(specs: Any) -> Optional[Dict[int, str]]:
    """Aliyun TSLs put enum maps in specs as either {value: label} or
    [{value, displayName}, …]."""
    if isinstance(specs, dict):
        # form 1: dict keyed by value
        items = []
        for k, v in specs.items():
            if k in ("unit", "step", "min", "max", "minValue", "maxValue",
                     "unitName", "unitDesc", "ratio", "scale", "precision"):
                continue
            try:
                items.append((int(k), str(v)))
            except (TypeError, ValueError):
                pass
        if items:
            return dict(items)
    if isinstance(specs, list):
        out = {}
        for it in specs:
            if not isinstance(it, dict):
                continue
            val = it.get("value", it.get("val"))
            label = it.get("displayName") or it.get("name") or it.get("label")
            if val is None or label is None:
                continue
            try:
                out[int(val)] = str(label)
            except (TypeError, ValueError):
                pass
        if out:
            return out
    return None


def _normalize_current_value(raw: Any):
    if raw in (None, ""):
        return None
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, (int, float)):
        return int(raw) if float(raw).is_integer() else raw
    text = str(raw).strip()
    if not text:
        return None
    low = text.lower()
    if low in ("true", "on"):
        return 1
    if low in ("false", "off"):
        return 0
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return text


# ── Loader ────────────────────────────────────────────────────────────────

_bundle_cache: Optional[dict] = None


def load_bundle(path: str = TSL_DUMP_PATH) -> dict:
    global _bundle_cache
    if _bundle_cache is not None:
        return _bundle_cache
    try:
        with open(path, "r", encoding="utf-8") as f:
            _bundle_cache = json.load(f)
    except (OSError, ValueError):
        _bundle_cache = {}
    return _bundle_cache


# ── Catalogs ──────────────────────────────────────────────────────────────

# Codes the bridge intentionally hides from HA discovery: handled via dedicated
# entities (output_power slider) or business-logic post-processing.
HIDDEN_CONTROL_CODES = set()


def get_switches() -> List[dict]:
    """Return TSL controls suitable for HA `switch` / `select` / `number` entities.

    Each entry:
      {code, name, id, kind, type, on, off, min, max, step, options}
    where `kind` is one of "switch", "select", "number".

    Reads from `properties` (full TSL with enum options + min/max/step), not
    from `controls` — the latter only carries current values, not specs.
    """
    bundle = load_bundle()
    # Prefer properties (full TSL); fall back to controls (legacy bundles).
    catalog = bundle.get("properties") or bundle.get("controls") or {}
    out: List[dict] = []
    for code, info in catalog.items():
        if code in HIDDEN_CONTROL_CODES:
            continue
        if not info.get("writable", True):
            continue
        ident = info.get("id")
        if ident is None:
            continue
        type_str = str(info.get("type") or "").upper()
        specs = info.get("specs") or {}
        entry = {
            "code": code,
            "name": info.get("name") or code,
            "id":   int(ident),
            "type": type_str,
            "current_value": info.get("current_value"),
        }
        if type_str == "BOOL":
            entry["kind"] = "switch"
            entry["on"]   = True
            entry["off"]  = False
        elif type_str in ("ENUM",):
            opts = _enum_options(specs)
            if opts:
                # Always a select — the cloud labels are richer than a bare
                # on/off pair, and even 2-value enums (Customised/Smart Socket)
                # carry meaning that disappears if we collapse to a switch.
                entry["kind"]    = "select"
                entry["options"] = opts
            else:
                # ENUM declared but options not exposed by the TSL — degrade to
                # a 1/0 switch as a last resort.
                entry["kind"] = "switch"
                entry["on"]   = 1
                entry["off"]  = 0
        elif type_str in ("INT", "INTEGER", "LONG", "UINT", "UINT16", "UINT32", "FLOAT", "DOUBLE"):
            lo, hi = _range(specs)
            entry["kind"] = "number"
            entry["min"]  = lo
            entry["max"]  = hi
            entry["step"] = _step(specs)
        else:
            # Complex writable ARRAY/STRUCT/TEXT controls need a dedicated UI
            # and encoder. Do not expose them as fake switches: toggling one
            # would send a meaningless 1/0 payload to schedules/measure_data.
            continue
        out.append(entry)
    return out


def get_sensors() -> List[dict]:
    """Return TSL properties suitable for HA `sensor` entities, plus the struct
    sub-fields the walker decodes.

    Each entry:
      {code, name, id, parent_id (optional), unit, device_class, state_class, step}
    """
    bundle = load_bundle()
    props = bundle.get("properties") or {}
    out: List[dict] = []
    seen: set = set()

    def _emit(code: str, info: dict, parent_id: Optional[int] = None,
              parent_code: str = "", parent_name: str = ""):
        if code in seen:
            return
        seen.add(code)
        specs = info.get("specs") or {}
        unit  = _unit_string(specs)
        dc, sc = _device_class(unit, code)
        name = info.get("name") or code
        if parent_name:
            name = f"{parent_name} {name}"
        entry = {
            "code":         code,
            "name":         name,
            "id":           info.get("id"),
            "parent_id":    parent_id,
            "parent_code":  parent_code,
            "unit":         unit,
            "device_class": dc,
            "state_class":  sc,
            "step":         _step(specs),
        }
        out.append(entry)

    # Whole-tree skips: container properties whose children duplicate or
    # conflict with the curated baseline (pack_data battery_voltage vs
    # battery_data battery_total_voltage, etc.) — drop the entire branch.
    _SKIP_TREE = {"pack_data"}

    for code, info in props.items():
        if info.get("writable"):
            # Writable properties are commands (handled in get_switches).
            continue
        if code in _SKIP_TREE:
            continue
        type_str = str(info.get("type") or "").upper()
        children = info.get("children") or {}
        if type_str in ("STRUCT", "OBJECT", "ARRAY"):
            if children:
                # Container — emit only its children (when the bridge knows how
                # to decode them). ARRAY's children duplicate per-slot fields
                # like `soc`/`battery_voltage` already covered by battery_data;
                # _emit() dedupes via `seen`.
                pid = info.get("id")
                parent_name = info.get("name") or code
                for ccode, cinfo in children.items():
                    _emit(ccode, cinfo, parent_id=pid, parent_code=code, parent_name=parent_name)
            # else: struct/array without exploded children → parser missed the
            # sub-list for this Aliyun variant; skip rather than emit a parent
            # sensor that would carry a list/dict value HA can't render.
        else:
            _emit(code, info)
    return out


# ── Bridge-shape adapters (legacy dict shapes) ────────────────────────────

# These mirror the legacy SWITCH_HEX / SENSOR_DEFS dict shapes so the bridge
# can `.update()` them with TSL-discovered extras without rewriting 30 call
# sites. The bridge's hardcoded literals stay as the Wonderfree/Landbook powerstation baseline;
# whatever new codes the TSL adds (heater_switch on a different model, a new
# pv_string_2_voltage, …) get layered on top automatically.

# Default icons inferred from the TSL code (best-effort — falls back to a
# generic icon if nothing matches). New users can still override per-code via
# the bridge's SWITCH_DISCOVERY_META if they want pretty icons.
_ICON_HINTS = [
    ("ac",      "mdi:power-socket-eu"),
    ("dc",      "mdi:current-dc"),
    ("grid",    "mdi:transmission-tower-export"),
    ("led",     "mdi:led-on"),
    ("light",   "mdi:lightbulb"),
    ("screen",  "mdi:monitor"),
    ("display", "mdi:monitor"),
    ("beep",    "mdi:volume-high"),
    ("buzzer",  "mdi:volume-high"),
    ("heater",  "mdi:radiator"),
    ("fan",     "mdi:fan"),
    ("battery", "mdi:battery"),
]


def _icon_for(code: str) -> Optional[str]:
    lc = code.lower()
    for needle, icon in _ICON_HINTS:
        if needle in lc:
            return icon
    return None


# Codes the baseline already represents under a different internal name; mapping
# from TSL code → bridge switch_id so we don't create duplicates.
_BASELINE_SWITCH_CODE_TO_ID = {}

# ENUM controls collapsed to a plain HA on/off switch instead of a multi-option
# select. Value = the ENUM index considered "ON"; any other index (including
# ones not listed) is reported as "OFF". Used for controls where only two
# states matter day-to-day and the extra options are rarely changed from HA —
# also sidesteps select entities flapping when the device firmware reports
# this code inconsistently across different frame types (see led_status_set:
# the "ON" index here is firmware-confirmed by a real TSL command in logs,
# index 0 is "Off").
ENUM_AS_SWITCH = {
    "led_status_set": 1,   # 0=Off, 1=High Brightness (2=Low Brightness, 3=SOS, 4=Strobe not exposed)
}

# TSL items that are not real switches/sensors — internal metadata, counters,
# or commands handled separately by the bridge.
_TSL_NOISE_PATTERNS = ()

# Mapping TSL sub-field code → existing baseline sensor id. When the walker
# decodes a struct/array child carrying the same physical quantity as a
# baseline sensor, we publish it under the baseline id so HA shows it on the
# entity the user already has (with curated name/precision/device_class) and
# no duplicate appears in Settings → Devices.
TSL_CHILD_TO_BASELINE = {}

_TSL_NOISE_EXACT = {
    "hmi_data_no",
}


def _is_noise(code: str) -> bool:
    if code in _TSL_NOISE_EXACT:
        return True
    lc = code.lower()
    return any(lc.endswith(suf) for suf in _TSL_NOISE_PATTERNS if suf.startswith("_")) \
        or any(p in lc for p in _TSL_NOISE_PATTERNS if not p.startswith("_"))


def build_switch_hex_overlay(existing: Optional[Dict[str, dict]] = None) -> Dict[str, dict]:
    """Return BOOL controls from the TSL using the TSL code as the entity id."""
    existing = existing or {}
    existing_ids = {k.lower() for k in existing.keys()}
    existing_codes = {str(v.get("code", "")).lower() for v in existing.values() if v.get("code")}

    out: Dict[str, dict] = {}
    for sw in get_switches():
        code = sw["code"]
        lc = code.lower()
        if sw.get("kind") != "switch" or str(sw.get("type") or "").upper() != "BOOL":
            continue
        if lc in existing_ids or lc in existing_codes:
            continue
        out[code] = {
            "name": sw.get("name") or code,
            "code": code,
            "id": int(sw["id"]),
            "type": "BOOL",
            "on": True,
            "off": False,
        }
    for code, on_value in ENUM_AS_SWITCH.items():
        lc = code.lower()
        if lc in existing_ids or lc in existing_codes or code in out:
            continue
        for sw in get_switches():
            if sw["code"] != code or sw.get("kind") != "select":
                continue
            opts = sw.get("options") or {}
            on_label = opts.get(on_value, "ON")
            current_value = _normalize_current_value(sw.get("current_value"))
            out[code] = {
                "name": sw.get("name") or code,
                "code": code,
                "id": int(sw["id"]),
                "type": "ENUM",
                "on": on_value,
                "off": 0 if on_value != 0 else 1,
                "_on_label": on_label,
            }
            if isinstance(current_value, int):
                out[code]["current_value"] = "ON" if current_value == on_value else "OFF"
            break
    return out

# Codes that have been previously published as MQTT discovery in earlier add-on
# versions but should NOT exist as switches. The bridge clears their retained
# discovery config at startup so HA forgets them.
RETAINED_SWITCH_CLEANUP = [
    "ac", "dc", "grid", "led", "screen", "beep", "slow_reporting",
    "mode",
    "power_retention_set",
    "smart_socket_mode",
    "timed_charge_connection",
    "timed_grid_connection",
    "screen_sleeptime_set",
    "high_frequency_reporting",
    "measure_data",
    "ac_switch", "dc_switch", "grid_power_switch_set",
    "beep_setting_set", "ac_charging_limit_set",
    # Any direct duplicate of the baseline internal names was published as a
    # separate switch in 0.3.86-first-run; clean them up.
]

RETAINED_SELECT_CLEANUP = [
    "high_frequency_reporting",
    "smart_socket_mode",
    "led_status_set",
]

def build_select_overlay(existing_switch_codes: Optional[set] = None) -> Dict[str, dict]:
    """Return ENUM controls that should appear as HA `select` entities.

    Shape: {code: {name, id, type:"ENUM", options:{value_int: label_str}}}
    Skips internal/noise codes and anything in ENUM_AS_SWITCH (those are
    exposed as a plain on/off switch by build_switch_hex_overlay instead)."""
    existing_codes = {c.lower() for c in (existing_switch_codes or set())}
    out: Dict[str, dict] = {}
    for sw in get_switches():
        if sw.get("kind") != "select":
            continue
        code = sw["code"]
        lc = code.lower()
        if lc in existing_codes or code in ENUM_AS_SWITCH:
            continue
        options = sw.get("options") or {}
        if not options:
            continue
        entry = {
            "code":    code,
            "name":    sw.get("name") or code,
            "id":      int(sw["id"]),
            "type":    "ENUM",
            "options": options,
        }
        current_value = _normalize_current_value(sw.get("current_value"))
        if isinstance(current_value, int) and current_value in options:
            entry["current_value"] = current_value
            entry["current_label"] = options[current_value]
        out[code] = entry
    return out


RETAINED_SENSOR_CLEANUP = [
    "battery_percentage", "battery_voltage", "battery_current", "battery_temp",
    "battery_total_power", "battery_remaining_wh", "remaining_time_minutes",
    "pv_input_power", "pv_panel_voltage", "grid_voltage", "grid_freq",
    "grid_b_power", "ac_input_power", "ac_output_power", "dc_output_power",
    "usb_a1_voltage", "usb_a1_power", "usb_a1_current",
    "usb_a2_voltage", "usb_a2_power", "usb_a2_current",
    "usb_a3_voltage", "usb_a3_power", "usb_a3_current",
    "usb_a4_voltage", "usb_a4_power", "usb_a4_current",
    "typec_1_voltage", "typec_1_power", "typec_1_current",
    "typec_2_voltage", "typec_2_power", "typec_2_current",
    "dc12v_voltage", "dc12v_power", "dc12v_current",
    "dc24v_voltage", "dc24v_power", "dc24v_current",
    "temp_inv", "temp_mppt", "temp_bms",
    "total_input_power", "total_output_power",
    "device_status", "fault_code", "fault_code_raw", "uptime_minutes_lan",
    "battery_cycles", "bms_allow_max_charge_current", "bms_mos_status",
    "battery_cell_01_voltage", "battery_cell_02_voltage", "battery_cell_03_voltage",
    "battery_cell_04_voltage", "battery_cell_05_voltage", "battery_cell_06_voltage",
    "battery_cell_07_voltage", "battery_cell_08_voltage", "battery_cell_09_voltage",
    "battery_cell_10_voltage", "battery_cell_11_voltage", "battery_cell_12_voltage",
    "battery_cell_13_voltage",
    "ac_charging_limit_set", "ac_data", "ac_switch", "battery_data",
    "beep_setting_set", "dc_data", "dc_switch", "device_key", "device_type",
    "grid_data", "grid_power_switch_set", "led_status_set", "output_power_set",
    "pack_data", "power_retention_set", "pv_data", "smart_socket_mode",
    "timed_charge_connection", "timed_grid_connection", "work_profile",
    "hmi_data", "temp_data", "bms_data", "bms_celldata", "measure_data",
    "power_generation", "load_power_consumption", "solar_panel_power_generation",
    "fault_code_information", "device_status_tsl",
    "device_status_raw", "fault_code_raw",
    "ac_data_ac_power", "ac_data_ac_voltage",
    "battery_data_soc", "battery_data_battery_total_power",
    "battery_data_battery_total_voltage", "battery_data_remaining_time",
    "battery_data_battery_temp",
    "dc_data_dc_total_power",
    "dc_data_dc_12v_power", "dc_data_dc_12v_voltage",
    "dc_data_dc_24v_power", "dc_data_dc_24v_voltage",
    "dc_data_typec_1_power", "dc_data_typec_1_voltage",
    "dc_data_typec_2_power", "dc_data_typec_2_voltage",
    "dc_data_usb_1_power", "dc_data_usb_1_voltage",
    "dc_data_usb_2_power", "dc_data_usb_2_voltage",
    "dc_data_usb_3_power", "dc_data_usb_3_voltage",
    "dc_data_usb_4_power", "dc_data_usb_4_voltage",
    "grid_data_grid_b_power", "grid_data_grid_frequency", "grid_data_grid_voltage",
    "pv_data_pv_total_power", "pv_data_pv_1_power", "pv_data_pv_1_voltage",
    # Struct parents the walker can't expand into useful per-field sensors
    "pv_data", "grid_data", "battery_data", "pack_data", "ac_data", "dc_data",
    "hmi_data", "temp_data", "bms_data", "bms_celldata",
    # Diagnostic / internal metadata
    "device_type", "mac_set", "device_dk",
    # Firmware-version codes published by earlier auto-discovery (the user has
    # the curated baseline Firmware Main/BMS/MPPT/INV behind a debug flag).
    "Firmware_Version_set", "Firmware_Version_bms",
    "Firmware_Version_mppt", "Firmware_Version_inv",
    "firmware_version", "firmware_version_set_tsl",
    # Counters/markers exposing TSL struct lengths — not actual telemetry
    "hmi_data_no", "temp_data_no", "bms_celldata_no",
    # Power-counter codes the device doesn't actually emit in LAN telemetry
    # (they're cloud-only daily totals — re-enabled later via a different code path)
    "load_power_consumption", "solar_panel_power_generation",
    # Cloud-only attributes — the add-on is LAN-only by design, so any field
    # that only the cloud knows is dropped (a "Sconosciuto" sensor is worse
    # than no sensor).
    "signal_strength", "signal_strength_set", "signalStrength",
    # TSL struct children published as duplicates of baseline sensors in earlier
    # overlay versions. The mapping table now routes them into the baseline
    # entities, so kill the orphans HA still shows.
    "soc", "battery_total_voltage", "remaining_time",
    "pv_total_power", "pv_1_power", "pv_1_voltage",
    "grid_frequency", "ac_voltage", "ac_power", "dc_total_power",
    "usb_1_voltage", "usb_1_power", "usb_2_voltage", "usb_2_power",
    "usb_3_voltage", "usb_3_power", "usb_4_voltage", "usb_4_power",
    "dc_12V_voltage", "dc_12V_power", "dc_24V_voltage", "dc_24V_power",
    "bms_mos_temp", "inv_temp_max", "mppt_temp_max",
    "CellVoltage1", "CellVoltage2", "CellVoltage3", "CellVoltage4",
    "CellVoltage5", "CellVoltage6", "CellVoltage7", "CellVoltage8",
    "CellVoltage9", "CellVoltage10", "CellVoltage11", "CellVoltage12",
    "CellVoltage13", "CellVoltage14",  # 14 not present in 13S pack
    "BatCycleCnt", "AllowMaxChgCurr", "MosStatus",
]


def build_sensor_defs_overlay(existing: Optional[Dict[str, tuple]] = None) -> Dict[str, tuple]:
    """Return TSL-discovered sensors in legacy SENSOR_DEFS shape, skipping noise,
    anything already in the baseline (case-insensitive), and anything that has a
    `TSL_CHILD_TO_BASELINE` mapping (those route their values to the baseline
    entity instead of creating a new one)."""
    existing = existing or {}
    baseline = {k.lower() for k in existing.keys()}
    mapped   = {k.lower() for k in TSL_CHILD_TO_BASELINE.keys()}
    out: Dict[str, tuple] = {}
    for s in get_sensors():
        code = s["code"]
        if _is_noise(code):
            continue
        if code.lower() in baseline:
            continue
        if code.lower() in mapped:
            continue
        out[code] = (
            s.get("name") or code,
            s.get("unit"),
            s.get("device_class"),
            s.get("state_class"),
        )
    return out


def build_number_overlay(existing_codes: Optional[set] = None) -> Dict[str, dict]:
    """Return writable numeric TSL controls as HA number entities."""
    existing = {c.lower() for c in (existing_codes or set())}
    out: Dict[str, dict] = {}
    for sw in get_switches():
        if sw.get("kind") != "number":
            continue
        code = sw["code"]
        if code.lower() in existing:
            continue
        entry = {
            "code": code,
            "name": sw.get("name") or code,
            "id": int(sw["id"]),
            "type": sw.get("type") or "INT",
            "min": sw.get("min"),
            "max": sw.get("max"),
            "step": sw.get("step"),
        }
        current_value = _normalize_current_value(sw.get("current_value"))
        if isinstance(current_value, (int, float)):
            entry["current_value"] = current_value
        out[code] = entry
    return out


def build_switch_meta_overlay() -> Dict[str, dict]:
    """Default icons for switches the user hasn't customized."""
    out: Dict[str, dict] = {}
    for sw in get_switches():
        if sw.get("kind") != "switch":
            continue
        icon = _icon_for(sw["code"])
        if icon:
            out[sw["code"]] = {"icon": icon}
    return out


