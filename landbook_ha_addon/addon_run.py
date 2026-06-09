import base64
import json
import logging
import os
import socket
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
log = logging.getLogger("addon_run")
APP_VERSION = "0.3.82"


def load_options():
    path = "/data/options.json"
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def add_arg(args, name, value):
    if value is None or value == "":
        return
    cli_name = name.replace("_", "-")
    if isinstance(value, bool):
        args.append(f"--{cli_name}" if value else f"--no-{cli_name}")
        return
    args.extend([f"--{cli_name}", str(value)])


def _on_off(value):
    val = str(value).strip().upper()
    if val in ("1", "TRUE", "ON"):
        return "ON"
    if val in ("0", "FALSE", "OFF"):
        return "OFF"
    return None


def _resource_values(payload):
    data = payload.get("data") or payload
    if isinstance(data, dict) and isinstance(data.get("customizeTslInfo"), list):
        values = {}
        for item in data["customizeTslInfo"]:
            code = item.get("resourceCode")
            if not code:
                continue
            val = item.get("resourceValce")
            try:
                val = json.loads(val)
            except Exception:
                pass
            values[code] = val
        return values
    if isinstance(data, list):
        return {item.get("id", ""): item.get("val", "") for item in data if isinstance(item, dict)}
    if isinstance(data, dict):
        return data
    return {}


def run_autodiscovery(options):
    email    = str(options.get("wf_email", "")).strip()
    password = str(options.get("wf_password", "")).strip()
    if not email or not password:
        raise SystemExit("wf_email/wf_password obbligatori: la LAN key deve essere scoperta dal cloud")
    platform = str(options.get("app", "landbook")).strip().lower()
    log.info(f"Cloud login: platform={platform} user={email[:3]}***")
    os.environ["WF_EMAIL"]    = email
    os.environ["WF_PASSWORD"] = password
    os.environ["PLATFORM"]    = platform
    try:
        from wf_autodiscovery import setup as autodiscovery_setup
        autodiscovery_setup(force=True)
    except SystemExit as e:
        log.error(f"Cloud login fallito: {e}")
        raise
    except Exception as e:
        log.error(f"Cloud login errore: {e}")
        raise
    lan_key_hex = os.environ.get("LAN_KEY_HEX", "").strip()
    if not lan_key_hex:
        raise SystemExit("LAN key non trovata dal cloud: controlla app/account o associazione dispositivo")
    try:
        options["key"] = base64.b64encode(bytes.fromhex(lan_key_hex)).decode("ascii")
        log.info("LAN key recuperata dal cloud")
    except Exception as e:
        raise SystemExit(f"Conversione LAN key fallita: {e}")
    device_key = os.environ.get("DEVICE_KEY", "").strip()
    if device_key:
        options["_device_key"] = device_key


def fetch_switch_states(options):
    import requests as _req
    token        = os.environ.get("WF_TOKEN", "")
    realtime_url = os.environ.get("REALTIME_ATTRS_URL", "")
    device_key   = os.environ.get("DEVICE_KEY", "")
    product_key  = os.environ.get("PRODUCT_KEY", "")
    if not all((token, realtime_url, device_key, product_key)):
        return {}
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
        attrs = _resource_values(j)
        ATTR_MAP = {
            "beepSwitch": "beep", "beep": "beep", "buzzer": "beep",
            "gridSwitch": "grid", "grid": "grid", "gridOutput": "grid", "gridOutputSwitch": "grid",
            "acSwitch": "ac", "ac": "ac", "acOutput": "ac", "acOutputSwitch": "ac",
            "dcSwitch": "dc", "dc": "dc", "dcOutput": "dc", "dcOutputSwitch": "dc",
            "ledSwitch": "led", "led": "led", "lightSwitch": "led",
            "screenSwitch": "screen", "screen": "screen", "displaySwitch": "screen",
            "slowReporting": "slow_reporting", "slowReport": "slow_reporting",
        }
        states = {}
        for cloud_key, switch_id in ATTR_MAP.items():
            if cloud_key in attrs and switch_id not in states:
                state = _on_off(attrs[cloud_key])
                if state:
                    states[switch_id] = state
        resource_bool_map = {
            "ac_switch": "ac",
            "dc_switch": "dc",
            "grid_power_switch_set": "grid",
            "beep_setting_set": "beep",
            "ac_charging_limit_set": "slow_reporting",
        }
        for resource, switch_id in resource_bool_map.items():
            if resource in attrs:
                state = _on_off(attrs[resource])
                if state:
                    states[switch_id] = state
        led = attrs.get("led_status_set")
        if led is not None:
            states["led"] = "OFF" if str(led).strip() == "0" else "ON"
        screen = attrs.get("screen_sleeptime_set")
        if screen is not None:
            states["screen"] = "ON" if str(screen).strip() == "0" else "OFF"
        mode = attrs.get("mode")
        if mode is not None:
            states["mode"] = {
                "0": "PPS",
                "1": "Micro-Inverter",
                "2": "Power Reserve Priority",
            }.get(str(mode).strip(), str(mode).strip())
        output_power = attrs.get("output_power_set")
        if output_power is not None:
            try:
                watts = int(float(output_power))
                if 0 < watts <= 2000:
                    states["output_power"] = str(watts)
            except (TypeError, ValueError):
                pass
        if states:
            log.info(f"Stati comandi dal cloud: {states}")
        return states
    except Exception as e:
        log.debug(f"fetch_switch_states errore: {e}")
        return {}


# ── Main ─────────────────────────────────────────────────────────────────────

options = load_options()

level_str = str(options.get("log_level", "info")).lower().strip()
logging.getLogger().setLevel({"debug": logging.DEBUG, "info": logging.INFO,
                               "warning": logging.WARNING, "error": logging.ERROR}.get(level_str, logging.INFO))
log.info(f"Landbook LAN Bridge {APP_VERSION} — log level: {level_str.upper()}")

run_autodiscovery(options)

device_key = options.pop("_device_key", "") or str(options.get("device_key", "")).strip()
topic = f"landbook/{device_key}" if device_key else "landbook/device"

# La LAN key viene recuperata dal cloud, ma gli stati comandi non devono
# arrivare dal cloud: devono seguire solo LAN o comandi Home Assistant.

# Verify MQTT reachability
try:
    with socket.create_connection((options.get("mqtt_host", "core-mosquitto"),
                                   int(options.get("mqtt_port", 1883))), timeout=5):
        log.info("MQTT reachable")
except Exception as exc:
    log.warning(f"MQTT NOT reachable: {exc}")

cmd = [sys.executable, "/app/landbook_ha_mqtt_bridge.py"]
for key in ("device_host", "device_port", "mqtt_host", "mqtt_port",
            "mqtt_user", "mqtt_password", "battery_capacity_wh", "key"):
    add_arg(cmd, key, options.get(key))
add_arg(cmd, "device_key", device_key)
add_arg(cmd, "topic", topic)

os.environ["LANDBOOK_LOG_LEVEL"] = level_str
log.info(f"Avvio bridge → {topic}")
os.execv(sys.executable, cmd)
