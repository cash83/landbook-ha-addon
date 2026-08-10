"""landbook.command_state — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    AC_STATE_WORDS,
    DC_STATE_WORDS,
    GRID_STATE_WORDS,
    LEGACY_COMMAND_STATE_CLEANUP,
    MODE_LABEL_BY_VAL,
    STATE_TAGS,
    STICKY_CMD_STATE_CODES,
    SWITCH_HEX,
    VALUE_STATES,
    _canonical_command_id,
    _dc_command_id,
    _dprint,
    _grid_command_id,
)

from landbook.ttlv_decode import (
    _extract_output_power_set,
)

from landbook.sensors import (
    words16,
)


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
        _init_val = initial.get(switch_id, b"")
        if _init_val in ("", b"") and switch_id in STICKY_CMD_STATE_CODES:
            # Niente azzeramento: si conserva il retained MQTT dell'ultima
            # sessione (unica fonte di stato per questi codici).
            continue
        mqtt.publish(f"{base_topic}/cmd_state/{switch_id}", _init_val, retain=True)
    # 0.10.4: i valori 'current' del catalogo TSL scaricato dal CLOUD NON vengono
    # piu' ripubblicati all'avvio. Sono l'ultima sincronizzazione che il cloud si
    # ricorda e possono essere semplicemente SBAGLIATI: caso misurato il 30/07/2026,
    # Working Mode pubblicato come 'Output Priority' mentre il device era davvero in
    # 'Normal Mode', con la correzione dalla LAN arrivata solo 3h48m dopo (il codice
    # 'mode' scende dalla LAN di rado, non e' nei payload frequenti). Il retained
    # MQTT della sessione precedente e' invece l'ULTIMO valore visto per davvero
    # sulla LAN, quindi e' sempre una fonte migliore: lo si lascia intatto e si
    # aspetta che sia la LAN a scriverci sopra. Alla primissima installazione le
    # entita' restano 'unknown' finche' il device non riporta il valore: meglio
    # vuoto che finto.
    #
    # 0.10.5: nemmeno il retained della sessione precedente e' garantito vero — se
    # la powerstation viene cambiata dal pannello o dall'app mentre il bridge e'
    # fermo, quel valore diventa vecchio esattamente come quello del cloud. Con
    # l'opzione `clear_command_states_on_start` (default ON) all'avvio si azzera
    # anche quello: le entita' restano 'unknown' finche' NON e' la LAN a dire il
    # valore reale. Costo: alcuni codici scendono dalla LAN di rado (il caso peggiore
    # misurato e' 'mode', ~3h48m), quindi possono restare vuoti a lungo dopo un
    # riavvio. Scelta esplicita dell'utente: meglio vuoto che potenzialmente falso.
    # Restano esclusi i codici STICKY (la LAN non li riporta MAI: azzerarli li
    # lascerebbe 'unknown' per sempre).
    if args is not None:
        _cmd_codes = list(getattr(args, "_tsl_select_catalog", {}) or {}) + \
                     list(getattr(args, "_tsl_number_catalog", {}) or {})
        _clear_on_start = bool(getattr(args, "clear_command_states_on_start", True))
        if _clear_on_start:
            _cleared = 0
            for _code in _cmd_codes:
                if _code in STICKY_CMD_STATE_CODES:
                    continue
                mqtt.publish(f"{base_topic}/cmd_state/{_code}", b"", retain=True)
                _cleared += 1
            print(
                f"[cmd_state] {_cleared} stati comando azzerati all'avvio: si aspetta "
                "il valore reale dalla LAN (niente valori dal cloud ne' dalla sessione "
                "precedente)",
                flush=True,
            )
        elif _cmd_codes:
            _dprint(
                f"[cmd_state] {len(_cmd_codes)} valori 'current' dal TSL cloud non "
                "pubblicati: si conserva il retained dell'ultima sessione LAN",
                flush=True,
            )


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


