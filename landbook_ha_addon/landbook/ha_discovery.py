"""landbook.ha_discovery — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    APP_VERSION,
    DEVICE_NAME,
    DEVICE_OBJECT_ID,
    FIRMWARE_SENSOR_IDS,
    FORCE_SENSOR_CODES,
    INTELLIGENT_CHARGING_POWER_ID,
    INTELLIGENT_CHARGING_WATTS,
    SENSOR_DEFS,
    SWITCH_DISCOVERY_META,
    SWITCH_HEX,
    SWITCH_OBJECT_ID_OVERRIDES,
    _BASELINE_SHADOWED_BY_SELECT,
    _dprint,
    _tsl_switch_meta,
)

from landbook.cache_store import (
    _device_key,
)

from landbook.smart_socket import (
    _publish_smart_socket_discovery,
)

from landbook.sensors import (
    _PUBLISHED_SENSOR_CONFIGS,
    publish_sensor_discovery_config,
)

STARTUP_LAN_SENSOR_DISCOVERY_IDS = (
    "battery_percentage",
    "battery_remaining_wh",
    "remaining_time_minutes",
)


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
    for sensor_id in STARTUP_LAN_SENSOR_DISCOVERY_IDS:
        publish_sensor_discovery_config(mqtt, base_topic, sensor_id)

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
    # I codici in FORCE_SENSOR_CODES vanno esposti come SENSORE, non come select.
    # Li estraiamo dal catalogo select (così non generano entità/comando select né
    # bloccano la pubblicazione sensore), ma conserviamo l'info TSL per il nudge di
    # login (es. high_frequency_reporting=3).
    for _forced in FORCE_SENSOR_CODES:
        _forced_info = _tsl_select_overlay.pop(_forced, None)
        if _forced == "high_frequency_reporting" and _forced_info:
            args._hfr_nudge_info = _forced_info
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
        # I comandi delle prese NON vengono più sottoscritti qui: sono gestiti dal
        # worker prese dedicato (SmartSocketWorker), del tutto indipendente dal loop
        # LAN, così restano operativi anche a powerstation offline/freeze.
    if not topics:
        print("no MQTT command topics to subscribe; TSL controls are empty", flush=True)
        return False
    mqtt.subscribe(topics)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Frame building & sending
# ══════════════════════════════════════════════════════════════════════════════
