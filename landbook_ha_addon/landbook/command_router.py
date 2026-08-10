"""landbook.command_router — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    GRID_OPPOSITE_WINDOW,
    INTELLIGENT_CHARGING_POWER_ID,
    INTELLIGENT_CHARGING_WATTS,
    SWITCH_HEX,
    _command_tx_allowed,
    _dprint,
    _grid_command_id,
)

from landbook.powerstation_commands import (
    _build_intelligent_charging_payload,
    _build_tsl_info_frame,
    _intelligent_charge_index_from_watts,
    _next_packet_id,
    _send_frame,
    _tsl_control_info,
)

from landbook.command_state import (
    _set_pending_command_state,
)


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

