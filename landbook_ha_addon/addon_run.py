import base64
import json
import logging
import os
import socket
import shutil
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
log = logging.getLogger("addon_run")
def _read_app_version() -> str:
    """Read version from config.yaml so bumping the addon only requires
    editing one file."""
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

APP_VERSION = _read_app_version()

LAN_KEY_CACHE_PATH = "/data/landbook_lan_key.json"
TSL_CACHE_PATH     = "/data/landbook_tsl.json"


def load_options():
    path = "/data/options.json"
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_cached_lan_key(email: str, platform: str) -> dict:
    """Return cached LAN key bundle if it matches the current account, else {}."""
    try:
        with open(LAN_KEY_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("email") != email or data.get("platform") != platform:
        return {}
    if not data.get("lan_key_hex") or not data.get("device_key"):
        return {}
    return data


def apply_cached_lan_key(options: dict, cached: dict) -> None:
    """Apply a cached LAN key only when the matching TSL cache is usable too."""
    if not cached:
        raise SystemExit("LAN key cache assente")
    if not _tsl_dump_is_fresh():
        raise SystemExit(
            "cloud non disponibile e TSL cache mancante/obsoleta: impossibile avviare "
            "il bridge TSL-only con la sola LAN key in cache"
        )
    os.environ["LAN_KEY_HEX"] = cached["lan_key_hex"]
    os.environ["DEVICE_KEY"] = cached["device_key"]
    if cached.get("product_key"):
        os.environ["PRODUCT_KEY"] = cached["product_key"]
    options["key"] = base64.b64encode(bytes.fromhex(cached["lan_key_hex"])).decode("ascii")
    options["_device_key"] = cached["device_key"]
    ensure_tsl_share_copy()


def _tsl_dump_is_fresh() -> bool:
    """Return True if /data/landbook_tsl.json was written by the current parser.

    Older addon versions wrote bundles with `specs=None` for ENUM properties
    (the parser dropped list specs by mistake), which prevented HA selects from
    being built. Detect those via a parser_version mismatch and trigger a cloud
    refresh."""
    try:
        from wf_autodiscovery import TSL_PARSER_VERSION
    except ImportError:
        return True  # don't block boot if the module isn't importable yet
    try:
        with open(TSL_CACHE_PATH, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, ValueError):
        return False
    return int(bundle.get("parser_version", 0) or 0) >= int(TSL_PARSER_VERSION)



def ensure_tsl_share_copy() -> None:
    """Expose the current TSL in /share at every boot, also when cloud is skipped.
    This lets the user download/check the exact schema used by the add-on."""
    src = TSL_CACHE_PATH
    dst = "/share/landbook_tsl.json"
    try:
        if os.path.exists(src) and os.path.getsize(src) > 0:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
            log.info(f"[TSL] Copia TSL salvata in {dst}")
    except Exception as e:
        log.warning(f"[TSL] copia in /share fallita: {e}")

def save_cached_lan_key(email: str, platform: str) -> None:
    bundle = {
        "email":       email,
        "platform":    platform,
        "lan_key_hex": os.environ.get("LAN_KEY_HEX", ""),
        "device_key":  os.environ.get("DEVICE_KEY", ""),
        "product_key": os.environ.get("PRODUCT_KEY", ""),
        "saved_at":    int(__import__("time").time()),
    }
    if not bundle["lan_key_hex"] or not bundle["device_key"]:
        return
    try:
        os.makedirs(os.path.dirname(LAN_KEY_CACHE_PATH), exist_ok=True)
        with open(LAN_KEY_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(bundle, f)
        log.info(f"LAN key cached in {LAN_KEY_CACHE_PATH}")
    except OSError as e:
        log.warning(f"LAN key cache write failed: {e}")


def add_arg(args, name, value):
    if value is None or value == "":
        return
    cli_name = name.replace("_", "-")
    if isinstance(value, bool):
        args.append(f"--{cli_name}" if value else f"--no-{cli_name}")
        return
    args.extend([f"--{cli_name}", str(value)])


def run_autodiscovery(options, force_cloud: bool = False):
    """Populate options["key"] and env vars from local cache first.

    Normal boots use the cached LAN key + TSL without contacting the cloud.
    Cloud is used only to bootstrap or refresh those local LAN credentials/schema;
    telemetry and command states still come only from LAN frames.
    """
    email    = str(options.get("wf_email", "")).strip()
    password = str(options.get("wf_password", "")).strip()
    if not email:
        raise SystemExit("wf_email obbligatorio per validare la cache LAN locale")
    platform = str(options.get("app", "landbook")).strip().lower()
    os.environ["WF_EMAIL"]    = email
    os.environ["WF_PASSWORD"] = password
    os.environ["PLATFORM"]    = platform
    cached = {} if force_cloud else load_cached_lan_key(email, platform)

    if not password:
        if not force_cloud and cached and _tsl_dump_is_fresh():
            log.info(f"Powerstation: LAN key e TSL in cache locale ({LAN_KEY_CACHE_PATH}) — bootstrap cloud non necessario")
            apply_cached_lan_key(options, cached)
            os.environ["LANDBOOK_CLOUD_BOOTSTRAP_ONLY"] = "1"
            return
        raise SystemExit("wf_password obbligatoria solo se serve recuperare LAN key/TSL dal cloud")

    if not force_cloud and cached and _tsl_dump_is_fresh():
        log.info(f"Powerstation: LAN key e TSL in cache locale ({LAN_KEY_CACHE_PATH}) — bootstrap cloud non necessario")
        apply_cached_lan_key(options, cached)
        os.environ["LANDBOOK_CLOUD_BOOTSTRAP_ONLY"] = "1"
        return

    if not force_cloud:
        if cached:
            log.warning("Powerstation: TSL cache mancante/obsoleta; cloud usato solo per rigenerare TSL/LAN key locali")
        else:
            log.warning("Powerstation: LAN key cache assente; cloud usato solo per bootstrap LAN key/TSL locali")

    log.info(f"Powerstation bootstrap cloud login: platform={platform} user={email[:3]}***")
    try:
        from wf_autodiscovery import setup as autodiscovery_setup
        autodiscovery_setup(force=True)
    except SystemExit as e:
        log.error(f"Cloud login fallito: {e}")
        if cached:
            apply_cached_lan_key(options, cached)
            log.warning("cloud non disponibile: uso LAN key e TSL cache locale")
            return
        raise
    except Exception as e:
        log.error(f"Cloud login errore: {e}")
        if cached:
            apply_cached_lan_key(options, cached)
            log.warning("cloud non disponibile: uso LAN key e TSL cache locale")
            return
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
    save_cached_lan_key(email, platform)
    ensure_tsl_share_copy()


# ── Main ─────────────────────────────────────────────────────────────────────

options = load_options()

level_str = str(options.get("log_level", "info")).lower().strip()
logging.getLogger().setLevel({"debug": logging.DEBUG, "info": logging.INFO,
                               "warning": logging.WARNING, "error": logging.ERROR}.get(level_str, logging.INFO))
log.info(f"Landbook LAN Bridge {APP_VERSION} — log level: {level_str.upper()}")

# 0.10.6 — fuso orario del log.
# Gli orari stampati dal bridge (FREEZE START / UNREACHABLE START) usano
# time.localtime(). Il Supervisor NON passa la variabile TZ a questo add-on
# (verificato: TZ non impostata), quindi senza questo blocco il container resta
# su UTC e ogni ora nel log e' sfasata rispetto alla history di Home Assistant,
# rendendo impossibile incrociare i due. L'opzione `timezone` (default
# Europe/Rome) imposta TZ + time.tzset() per l'intero processo, bridge incluso.
# Ordine: opzione dell'add-on (se lo store ne ha gia' recepito lo schema) →
# ENV TZ → default. Il default e' nel codice e non solo nel Dockerfile perche'
# ne' il Supervisor ne' l'ENV dell'immagine si sono dimostrati affidabili qui.
# Se dopo questo il log stampa ancora UTC+0000, manca tzdata nell'immagine.
_tz = (
    str(options.get("timezone", "") or "").strip()
    or os.environ.get("TZ", "").strip()
    or "Europe/Rome"
)
if _tz:
    os.environ["TZ"] = _tz
    try:
        time.tzset()
    except AttributeError:
        pass  # non-Unix: si resta sul fuso di default
log.info(
    "Fuso orario del log: %s (TZ=%s) — ora locale %s",
    time.strftime("%Z%z"),
    os.environ.get("TZ", "non impostata"),
    time.strftime("%Y-%m-%d %H:%M:%S"),
)

run_autodiscovery(options)

device_key = options.pop("_device_key", "") or str(options.get("device_key", "")).strip()
topic = f"landbook/{device_key}" if device_key else "landbook/device"

# La LAN key/TSL arrivano dalla cache locale; il cloud interviene solo per
# bootstrap/refresh se la cache manca o la LAN key non è più valida.
# Gli stati della powerstation non arrivano dal cloud: seguono solo LAN o
# comandi Home Assistant. Le smart socket restano gestite dal loro worker separato.

# Verify MQTT reachability
try:
    with socket.create_connection((options.get("mqtt_host", "core-mosquitto"),
                                   int(options.get("mqtt_port", 1883))), timeout=5):
        log.info("MQTT reachable")
except Exception as exc:
    log.warning(f"MQTT NOT reachable: {exc}")

cmd = [sys.executable, "/app/landbook_ha_mqtt_bridge.py"]
for key in ("device_host", "device_port", "mqtt_host", "mqtt_port",
            "mqtt_user", "mqtt_password", "battery_capacity_wh",
            "smart_socket_poll_interval",
            "smart_socket_1_device_key", "smart_socket_1_product_key", "smart_socket_1_name",
            "smart_socket_2_device_key", "smart_socket_2_product_key", "smart_socket_2_name",
            "key"):
    add_arg(cmd, key, options.get(key))
add_arg(cmd, "freeze_detection_enabled", bool(options.get("freeze_detection_enabled", True)))
add_arg(cmd, "smart_sockets_enabled", bool(options.get("smart_sockets_enabled", True)))
add_arg(cmd, "clear_command_states_on_start",
        bool(options.get("clear_command_states_on_start", True)))
add_arg(cmd, "device_key", device_key)
add_arg(cmd, "topic", topic)

os.environ["LANDBOOK_LOG_LEVEL"] = level_str
log.info(f"Avvio bridge → {topic}")
os.execv(sys.executable, cmd)
