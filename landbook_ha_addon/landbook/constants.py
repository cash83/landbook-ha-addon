"""landbook.constants — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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



def _is_debug():
    return os.environ.get("LANDBOOK_LOG_LEVEL", "info").lower() == "debug"

def _dprint(*args, **kwargs):
    if _is_debug():
        import builtins
        builtins.print(*args, **kwargs)



# ── Timing ───────────────────────────────────────────────────────────────────
RXDUMP_EVERY           = 5     # diagnostica: max un [rxdump] ogni N secondi (solo debug)
HEARTBEAT_INTERVAL     = 10    # LAN keepalive (seconds)
MQTT_PING_INTERVAL     = 30    # MQTT keepalive
FRAME_SILENCE_TIMEOUT  = 30    # tollera il ciclo bus_mask
# DEPRECATO (0.9.34): watchdog "no sensor data" rimosso perche' irraggiungibile
# (last_sensor_rx == last_frame_rx, e "no frames" a 30s scattava sempre prima).
# Costante lasciata solo per compatibilita' con il testo dell'argparse.
SENSOR_RECONNECT_AFTER      = 50  # (non piu' usato nella logica)
                                   # (alzato da 30s: il device cicla naturalmente Low/LAN+WiFi reporting
                                   # ogni ~28-30s, e una soglia troppo vicina scambiava quel ciclo normale
                                   # per un freeze, causando reconnect inutili)
BUS_REFRESH_MIN_GAP    = 5     # debounce: non rimandare bus_mask/bus_refresh se già inviati da meno di Ns
SENSOR_SILENCE_RESTART = 180  # dopo 3 min senza sensori: riavvio processo
# Watchdog telemetria RICCA: la powerstation, pur restando connessa al WiFi e
# mandando frame minimi (solo battery_voltage), va in DEEP SLEEP e smette di
# inviare il frame work_profile "ricco" (SOC, stato, temperature, celle). Un nuovo
# login LAN NON la sveglia: l'UNICO risveglio è la perdita dell'associazione WiFi
# (toggle del WiFi del router, fatto dall'automazione HA sull'evento wifi_frozen).
# Perciò, se per RICH_TELEMETRY_ALERT secondi non arriva un frame ricco,
# pubblichiamo wifi_frozen così l'automazione ricicla il WiFi e risveglia il device.
RICH_TELEMETRY_ALERT   = 60   # 60s senza frame ricco → pubblica wifi_frozen (toggle WiFi).
                              # Misurato: un'assenza >=45s si e' SEMPRE evoluta in freeze reale
                              # (0 falsi positivi su 12 rilevazioni), quindi non ha senso
                              # aspettare 120s: il toggle e' l'unica cosa che sveglia il device.

# NOTA (0.9.32): la "sveglia mirata BMS" (bus_mask stretta sui soli blocchi ricchi)
# e' stata PROVATA e RIMOSSA: su questo firmware non ha alcun effetto. Misurato sul
# campo: 12 richieste mirate -> 0 risvegli. Il modulo continua a rispondere dalla
# cache. L'UNICA cosa che risveglia davvero i sottosistemi (BMS/inverter/MPPT) e' la
# perdita dell'associazione WiFi, cioe' il toggle del WiFi del router fatto
# dall'automazione HA sull'evento wifi_frozen. Per questo la soglia e' stata abbassata
# a 60s: inutile aspettare, tanto solo il toggle funziona.
RICH_ALERT_COOLDOWN    = 90   # ri-pubblica wifi_frozen (nuovo toggle) dopo ~90s se ancora fermo.
                              # Deve lasciare al router il tempo di ciclare il WiFi e al device
                              # di riassociarsi: sul campo il primo toggle e' sempre bastato.
RICH_ALERT_MAX_ATTEMPTS = 3   # dopo N toggle WiFi falliti: rinuncia (NON spegne
                              # l'addon: prese e frame minimi continuano). Il conteggio
                              # riparte da 0 appena torna un frame ricco.
# ── Quando marcare la powerstation OFFLINE (regola 0.10.8) ────────────────
# NON e' piu' una soglia di tempo sul silenzio della telemetria: e' l'ESITO
# dei tentativi di recupero. Regola voluta dall'utente e confermata da mesi di
# log: dal 1o (e dal 2o) freeze il device si riprende SEMPRE, quindi far
# sparire le entita' li' e' solo dannoso — in 0.10.6 una soglia a 40s rendeva
# 'unavailable' anche switch/select/number (availability e' del DEVICE, non
# dei soli sensori) proprio mentre il device era ancora comandabile, e i
# comandi venivano rifiutati ("command dropped (no sensor data yet)").
# Quindi: si resta ONLINE per tutto il ciclo normale di recupero, e si va
# offline SOLO quando i RICH_ALERT_MAX_ATTEMPTS toggle sono stati spesi invano
# e anche l'ultimo ha avuto la sua finestra. L'add-on NON si ferma: le prese
# hanno availability separata e continuano a funzionare.
RICH_STALE_OFFLINE_AFTER = 90  # secondi da concedere DOPO l'ultimo toggle fallito
                               # (il 3o) prima di dichiarare offline la powerstation.
                               # Allineato a RICH_ALERT_COOLDOWN: e' la stessa finestra
                               # che si darebbe a un toggle successivo, se ce ne fosse uno.
# Chiavi che compaiono SOLO nel frame ricco/work_profile: se una di queste è nel
# decoded, abbiamo appena ricevuto telemetria ricca.
RICH_TELEMETRY_MARKERS = frozenset({
    "device_status", "battery_percentage", "work_profile",
    "temp_bms", "temp_inv", "temp_mppt", "fault_code",
})
REPORT_RESUBSCRIBE     = 120   # subscription rara
BUS_MASK_INTERVAL      = 10    # simple LAN: bus_mask + bus_refresh fissi ogni ~10s
RECONNECT_DELAY_INIT   = 2.0   # recovery LAN rapido dopo freeze/unreachable
RECONNECT_DELAY_MAX    = 5.0   # non aspettare 17/25/30s tra retry
UNREACHABLE_RESTART    = 180   # restart process after 3 min unreachable
UNREACHABLE_WIFI_FROZEN_ALERT = 30  # dopo ~30s LAN irraggiungibile: alert wifi_frozen

# ── Rinuncia (0.10.1): powerstation semplicemente SPENTA ───────────────────
# Esauriti i RICH_ALERT_MAX_ATTEMPTS toggle WiFi con la LAN ancora hard-
# unreachable, il device è spento (o irraggiungibile in modo permanente): non
# ha senso continuare a riavviare il processo ogni UNREACHABLE_RESTART secondi
# (login cloud + TSL discovery + ripubblicazione di ~220 entità ogni 3 minuti,
# e reset del timer di polling delle prese). In "giveup mode" il bridge:
#   - pubblica availability=offline (i sensori powerstation → unavailable,
#     niente valori fantasma);
#   - NON si riavvia più;
#   - rallenta i retry a UNREACHABLE_GIVEUP_RECONNECT_DELAY, così quando la
#     powerstation viene riaccesa torna su da sola senza intervento.
# Il worker delle smart socket è un thread dello stesso processo: non
# riavviarsi è ciò che lo tiene vivo e con il suo poll interval intatto.
UNREACHABLE_GIVEUP_RECONNECT_DELAY = 50

# ── Alert 'sensor_silence' differito (0.10.2) ──────────────────────────────
# "no frames per 30s" = ZERO byte ricevuti. In quell'istante freeze reale e
# powerstation SPENTA sono indistinguibili, ma il toggle del WiFi del router ha
# senso solo nel primo caso (deep sleep = il device continua a mandare i frame
# minimi; se non arriva NULLA il device non c'è). L'alert resta quindi pendente
# e viene pubblicato solo quando il connect successivo riesce, cioè quando il
# device si dimostra raggiungibile. Se arriva hard-unreachable viene scartato.
# Il TTL evita che resti appeso in casi ambigui (es. loop broken-pipe).
PENDING_SILENCE_ALERT_TTL = 120

# ── Persistenza stato recovery tra i RESTART DI PROCESSO (0.9.37) ──────────
# Bug osservato sul campo (freeze serale 19:48→22:00+): il toggle WiFi rende la
# LAN irraggiungibile, dopo UNREACHABLE_RESTART il bridge riavvia sé stesso e il
# riavvio AZZERAVA rich_alert_streak → "tentativo 1/3" all'infinito, mai 2/3 o
# 3/3, router WiFi ciclato ogni ~3 minuti per ore. Il contatore ora sopravvive
# al restart su file; si azzera solo al ritorno di un frame ricco o dopo TTL.
RECOVERY_STATE_FILE = "/data/landbook_recovery_state.json"
RECOVERY_STATE_TTL  = 3600  # 1 ora: dopo 3 toggle falliti, pausa di un'ora prima
                            # di concedere un nuovo giro di tentativi (richiesta
                            # esplicita: niente cicli del router più spesso di così)



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
                 os.path.join(os.path.dirname(__file__), "config.yaml"),
                 os.path.join(os.path.dirname(__file__), "..", "config.yaml")):
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

# Switch il cui stato NON è ri-derivabile dalla telemetria: il firmware lo
# riporta solo come eco subito dopo un comando (osservato: beep 4 frame su
# 10k righe di log). Per questi NON azzeriamo il cmd_state retained all'avvio:
# l'ultimo valore pubblicato dal bridge al momento del comando è la miglior
# stima e senza di esso l'entità HA resta "unknown" (doppio pulsante).
STICKY_CMD_STATE_CODES = {"beep_setting_set"}

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

# Codici writable nel TSL che vogliamo comunque esporre come SENSORE di sola
# lettura invece che come select/switch/number. high_frequency_reporting è un
# ENUM writable, ma impostarlo da HA è inutile (il device oscilla Low/High da
# solo ~ogni 30s): serve solo osservare in che modalità sta → sensore.
FORCE_SENSOR_CODES = {"high_frequency_reporting"}
SENSOR_DEFS["high_frequency_reporting"] = ("High Frequency Reporting", None, None, None)

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
# Struct id decodificati come SCALARI (frame keepalive/vuoti oppure echi tipo
# grid_data:91 = soc, battery_data:365 = remaining_time). Mai valori reali:
# vengono rimossi dal decoded PRIMA della pipeline; se il frame resta vuoto
# viene scartato del tutto (niente log "decoded:", niente publish MQTT).
STRUCT_SCALAR_JUNK_KEYS = (
    "pv_data", "grid_data", "battery_data", "dc_data", "ac_data",
    "pack_data", "measure_data",
)
NON_MEANINGFUL_SENSOR_KEYS = {
    "ac_data", "battery_data", "dc_data", "grid_data", "pv_data", "pack_data",
    "measure_data", "temp_data_no", "bms_celldata_no", "work_profile",
    "device_key", "device_type",
    "output_power_set", "smart_socket_mode", "power_retention_set",
    "high_frequency_reporting",
}



DEVICE_OBJECT_ID = "landbook"

SWITCH_OBJECT_ID_OVERRIDES = {}
_DIAGNOSTIC_SENSOR_IDS = set()
_DIAGNOSTIC_PREFIXES = ()



def _restart_process(args) -> None:
    """Self-restart del bridge preservando lo stato 'online' delle prese."""
    from landbook.smart_socket import _stop_socket_liveness
    _stop_socket_liveness(args)
    os.execv(sys.executable, [sys.executable] + sys.argv)



def _boolish(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "on", "yes", "y")



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


