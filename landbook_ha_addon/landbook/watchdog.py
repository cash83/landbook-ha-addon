"""landbook.watchdog — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    RECOVERY_STATE_FILE,
    RECOVERY_STATE_TTL,
)


def _load_recovery_state():
    try:
        with open(RECOVERY_STATE_FILE) as fh:
            st = json.load(fh)
        if time.time() - float(st.get("ts", 0)) > RECOVERY_STATE_TTL:
            return None
        return st
    except Exception:
        return None


def _save_recovery_state(streak, last_alert):
    try:
        with open(RECOVERY_STATE_FILE, "w") as fh:
            json.dump({"rich_alert_streak": int(streak),
                       "last_rich_alert": float(last_alert),
                       "ts": time.time()}, fh)
    except Exception:
        pass  # best-effort: senza /data (dev) si degrada al comportamento vecchio


def _clear_recovery_state():
    try:
        os.remove(RECOVERY_STATE_FILE)
    except Exception:
        pass

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


def stop_addon_after_freeze(mqtt, availability_topic, topic, streak, duration):
    """DISABILITATA: non spegne più l'add-on.

    Storicamente usciva dal processo (SystemExit) dopo N freeze consecutivi. Ma
    il worker delle smart socket gira come thread daemon nello STESSO processo:
    uscire spegneva anche le prese cloud, indipendenti dalla LAN della
    powerstation. Ora pubblica solo l'alert wifi_frozen e RITORNA, così il loop
    principale continua a riconnettersi senza mai far cadere le prese.
    """
    print(
        f"Freeze consecutivi={streak}: alert wifi_frozen (auto-shutdown disabilitato, "
        "prese cloud indipendenti)",
        flush=True,
    )
    try:
        publish_wifi_frozen_alert(
            mqtt,
            topic,
            reason="freeze_streak_persistent",
            streak=streak,
            duration=duration,
        )
    except Exception as exc:
        print(f"MQTT wifi_frozen alert failed: {exc}", flush=True)
    # Nessun publish 'offline', nessun disconnect, nessun SystemExit: il processo
    # (e con esso il thread delle prese) deve restare vivo.
    return

# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════



