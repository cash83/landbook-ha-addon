"""landbook.sensors — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    AC_TRANSIENT_ZERO_KEYS,
    DC_OUTPUT_SENSOR_KEYS,
    DEVICE_KEY,
    DEVICE_NAME,
    DEVICE_OBJECT_ID,
    DEVICE_STATUS_LABELS,
    EXPIRING_SENSOR_IDS,
    FAULT_CODE_LABELS,
    FORCE_SENSOR_CODES,
    NON_MEANINGFUL_SENSOR_KEYS,
    SENSOR_DEFS,
    SENSOR_DISPLAY_PRECISION,
    SWITCH_HEX,
    _DIAGNOSTIC_PREFIXES,
    _DIAGNOSTIC_SENSOR_IDS,
    _dc_command_id,
    _grid_command_id,
)

from landbook.ttlv_decode import (
    calculate_total_output_power,
)

from landbook.powerstation_commands import (
    _load_tsl_controls,
)

from landbook_tsl_discovery import (
    RETAINED_SENSOR_CLEANUP,
)


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

def _entity_category(key: str):
    if key in _DIAGNOSTIC_SENSOR_IDS:
        return "diagnostic"
    if any(key.startswith(p) for p in _DIAGNOSTIC_PREFIXES):
        return "diagnostic"
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Decoder helpers  (protocol reverse-engineering — do not modify)
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
    # Codici forzati come sensore (es. high_frequency_reporting): esposti come
    # lettura anche se nel TSL sono writable — bypassano il blocco "writable" e
    # l'esclusione select/number sotto.
    if key in FORCE_SENSOR_CODES:
        return True
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
    # Powerstation values are LAN telemetry. The device rotates sensor groups, so
    # unchanged values still need to refresh in HA when the bridge republishes
    # the last LAN-observed state on each useful LAN frame.
    config["force_update"] = True
    mqtt.publish(f"homeassistant/sensor/{device_key}/{sensor_id}/config", json.dumps(config), retain=True)
    _PUBLISHED_SENSOR_CONFIGS.add(sensor_id)


def publish_sensor_cache(mqtt, base_topic, cache, keys=None, args=None):
    sensor_ids = list(cache.keys()) if keys is None else list(keys)
    for key in sensor_ids:
        if key in cache and _is_publishable_sensor(key, cache, args):
            publish_sensor_discovery_config(mqtt, base_topic, key)
            # Startup clears retained sensor states first; retain live LAN values
            # so Home Assistant does not fall back to unknown after MQTT reloads.
            mqtt.publish(f"{base_topic}/sensors/{key}", str(_sensor_value(key, cache[key])), retain=True)


def clear_retained_sensor_states(mqtt, base_topic):
    for key in sorted(set(SENSOR_DEFS) | set(RETAINED_SENSOR_CLEANUP)):
        mqtt.publish(f"{base_topic}/sensors/{key}", b"", retain=True)


# ══════════════════════════════════════════════════════════════════════════════
# Derived sensors & state tracking
# ══════════════════════════════════════════════════════════════════════════════


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
