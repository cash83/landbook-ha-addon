from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import string
import threading
import time
import traceback
import urllib.parse
from typing import Any

import requests
from Crypto.Cipher import AES
import paho.mqtt.client as mqtt


OPTIONS_PATH = "/data/options.json"
KEY_CACHE_PATH = "/data/landbook_lan_key.json"
HOST_CACHE_PATH = "/data/landbook_lan_host.json"
# Written under the old development name; renamed on first start so the cached
# LAN key survives and the cloud login is not needed again.
LEGACY_STATE_PATHS = {
    KEY_CACHE_PATH: "/data/test_powerstation_lan_key.json",
    HOST_CACHE_PATH: "/data/test_powerstation_lan_host.json",
}


def migrate_legacy_state() -> None:
    for current, legacy in LEGACY_STATE_PATHS.items():
        if os.path.exists(current) or not os.path.exists(legacy):
            continue
        try:
            os.replace(legacy, current)
        except OSError as exc:
            log(f"could not rename {legacy}: {exc}", "warning")
        else:
            log(f"state file renamed: {legacy} -> {current}")
TSL_DATA_PATH = "/data/landbook_tsl.json"
TSL_SHARE_COPY_PATH = "/share/landbook_tsl.json"
TSL_PATHS = (TSL_DATA_PATH, TSL_SHARE_COPY_PATH)
PLATFORMS_PATH = "/app/platforms.json"

DISCOVERY_PORT = 6606
DEFAULT_CONTROL_PORT = 6607
CMD_DISCOVERY_PROBE = 28720
CMD_DISCOVERY_REPLY = 28721
CMD_HELLO = 28722
CMD_NONCE = 28723
CMD_LOGIN = 28724
CMD_LOGIN_RESULT = 28725
CMD_WRITE_ACK = 28726
CMD_PING = 28727
CMD_PONG = 28728
CMD_HEARTBEAT = 28729
CMD_READ = 17
CMD_WRITE = 19
CMD_REPORT = 20
MAX_UDP_SCAN_HOSTS = 512

POWERSTATION_PRODUCT_KEYS = {"p11tpn", "p11uve"}
READ_EXCLUDED_IDS = {47}
P11TPN_FALLBACK_READ_IDS = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
]
RAW_DUPLICATE_KEYS = {
    "ac_power",
    "battery_power",
    "device_status_raw",
    "fault_code_raw",
    "firmware_version_bms",
    "firmware_version_inv",
    "firmware_version_mppt",
    "firmware_version_set",
    "Firmware_Version_bms",
    "Firmware_Version_inv",
    "Firmware_Version_mppt",
    "Firmware_Version_set",
    "high_frequency_reporting",
    "load_power_consumption",
    "solar_panel_power_generation",
    "week",
    "start_time",
    "end_time",
    "timed_charge_power",
    "timed_grid_connection_power",
    "soc",
    "remaining_time",
    "battery_total_voltage",
    "pack_num",
    "pv_data",
    "pv_total_power",
    "pv_1_power",
    "grid_frequency",
    "ac_power",
    "dc_total_power",
    "bms_mos_temp",
    "inv_temp_max",
    "mppt_temp_max",
    "BatCycleCnt",
    "AllowMaxChgCurr",
    "MosStatus",
    "hmi_data_no",
    "temp_data_no",
    "bms_celldata_no",
    "mac_set",
}
RAW_DUPLICATE_KEYS.update({f"CellVoltage{i}" for i in range(1, 15)})
RAW_DUPLICATE_KEYS.add("battery_cell_14_voltage")
PUBLISH_SENSOR_KEYS = {
    "lan_connection",
    "status",
    "device_status",
    "fault_code",
    "battery_percentage",
    "battery_remaining_wh",
    "battery_voltage",
    "battery_current",
    "battery_total_power",
    "battery_temp",
    "remaining_time_minutes",
    "pv_input_power",
    # Arriva SOLO nella risposta alla richiesta esplicita (cmd 17), mai nei
    # report spontanei: per questo non si era mai visto. La richiesta la
    # facciamo gia' ogni rearm_interval, quindi il dato era gia' in casa.
    "pv_1_voltage",
    "total_input_power",
    "ac_input_power",
    "ac_output_power",
    "ac_voltage",
    "grid_b_power",
    "grid_voltage",
    "total_output_power",
    "dc_12V_power",
    "dc_12V_voltage",
    "dc_24V_power",
    "dc_24V_voltage",
    "typec_1_power",
    "typec_1_voltage",
    "typec_2_power",
    "typec_2_voltage",
    "usb_1_power",
    "usb_1_voltage",
    "usb_2_power",
    "usb_2_voltage",
    "usb_3_power",
    "usb_3_voltage",
    "usb_4_power",
    "usb_4_voltage",
    "temp_bms",
    "temp_inv",
    "temp_mppt",
    "signal_strength_set",
    # Salute del pacco: arrivano a ogni frame del BMS e finora venivano scartati.
    # I cicli dicono quanto e' stata usata davvero la batteria, la corrente
    # massima concessa dice se il BMS sta limitando la carica.
    "battery_cycles",
    "bms_allow_max_charge_current",
    "bms_mos_status",
}
PUBLISH_SENSOR_KEYS.update({f"battery_cell_{i:02d}_voltage" for i in range(1, 14)})
PUBLISH_SENSOR_SLUGS = {slug for key in PUBLISH_SENSOR_KEYS for slug in (re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9_]+", "_", key.strip().lower())).strip("_"),)}
MAIN_TOPIC_PREFIX = "landbook"
MAIN_DEVICE_NAME = "Landbook LAN Device"
MAIN_DEVICE_OBJECT_ID = "landbook"
# In standby this station really does report days of autonomy - 9800 minutes at
# 73%, and the phone app shows the same 6 days 19 hours. The old 24-hour window
# threw that away as noise and left the sensor stuck on an older value. The
# product model declares the field up to 65535 minutes.
REMAINING_TIME_MAX_MINUTES = 65535

FREEZE_ALERT_AFTER = 90
FREEZE_ALERT_COOLDOWN = 50
DIAGNOSTIC_SENSOR_SLUGS = {
    "signal_strength_set",
    "lan_connection",
    "bms_mos_status",
    "battery_cycles",
    "bms_allow_max_charge_current",
    "temp_bms",
    "temp_inv",
    "temp_mppt",
}
DIAGNOSTIC_SENSOR_SLUGS.update({f"battery_cell_{i:02d}_voltage" for i in range(1, 14)})


def entity_category_for(key: str) -> str | None:
    return "diagnostic" if slugify(key) in DIAGNOSTIC_SENSOR_SLUGS else None


COMPAT_SENSOR_ID_OVERRIDES = {
    "dc_12v_power": "dc12v_power",
    "dc_12v_voltage": "dc12v_voltage",
    "dc_24v_power": "dc24v_power",
    "dc_24v_voltage": "dc24v_voltage",
    "usb_1_power": "usb_a1_power",
    "usb_1_voltage": "usb_a1_voltage",
    "usb_2_power": "usb_a2_power",
    "usb_2_voltage": "usb_a2_voltage",
    "usb_3_power": "usb_a3_power",
    "usb_3_voltage": "usb_a3_voltage",
    "usb_4_power": "usb_a4_power",
    "usb_4_voltage": "usb_a4_voltage",
}
COMPAT_SENSOR_NAME_OVERRIDES = {
    "pv_1_voltage": "PV1 Voltage",
    "battery_cycles": "Cicli batteria",
    "bms_allow_max_charge_current": "Corrente massima di carica",
    "bms_mos_status": "Stato MOS del BMS",
    "lan_connection": "LAN Connection",
    "battery_percentage": "Battery",
    "battery_remaining_wh": "Battery Remaining",
    "battery_total_power": "Battery Power",
    "grid_b_power": "Grid AC Power",
    "remaining_time_minutes": "Tempo residuo",
}
COMPAT_SWITCH_OBJECT_IDS = {
    "ac_switch": "ac_switch",
    "dc_switch": "dc_switch",
    "grid_power_switch_set": "wonderfree_power_station_on_grid_output_swith",
    "beep_setting_set": "wonderfree_power_station_buzzer_setting",
    "ac_charging_limit_set": "wonderfree_power_station_silent_charge_slow_charge",
}
COMPAT_SELECT_OBJECT_IDS = {
    "mode": "landbook_fppt_t2400_modalita",
    "power_retention_set": "landbook_fppt_t2400_soc_discharge_setting",
    "screen_sleeptime_set": "landbook_fppt_t2400_screen_off_time",
    "smart_socket_mode": "landbook_fppt_t2400_power_consumption_plan",
}
COMPAT_NUMBER_OBJECT_IDS = {
    "output_power_set": "wonderfree_power_station_potenza_rete",
}
HIDDEN_CONTROL_CODES = {
    "quec_x_clear_data",
    "measure_data",
    "timed_charge_connection",
    "timed_grid_connection",
    "high_frequency_reporting",
}
HFR_MODE_LABELS = {
    0: "Infrequente",
    1: "LAN HFR",
    2: "WiFi HFR",
    3: "LAN+WiFi HFR",
}
ENUM_AS_SWITCH = {
    "led_status_set": 1,
}
SMART_SOCKET_PRODUCT_KEYS = {"p11spk"}
SMART_SOCKET_SENSOR_DEFS = {
    "power": ("Power", "W", "power", "measurement", 0),
    "voltage": ("Voltage", "V", "voltage", "measurement", 1),
    "current": ("Current", "A", "current", "measurement", 3),
    "apparent_power": ("Apparent Power", "VA", "apparent_power", "measurement", 0),
    "power_factor": ("Power Factor", None, "power_factor", "measurement", 3),
    "energy": ("Energy", "kWh", "energy", "total_increasing", 2),
}
SMART_SOCKET_ON_HEX = "aa aa 00 07 21 00 05 00 13 00 09"
SMART_SOCKET_OFF_HEX = "aa aa 00 07 21 00 05 00 13 00 08"
SMART_SOCKET_NOT_FOUND_LIMIT = 3
SOCKET_TOKEN_SKEW = 600
SOCKET_TOKEN_FALLBACK_TTL = 7200



def now_s() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str, level: str = "info") -> None:
    levels = {"debug": 10, "info": 20, "warning": 30, "error": 40}
    current = levels.get(str(os.environ.get("LOG_LEVEL", "info")).lower(), 20)
    if levels.get(level, 20) >= current:
        print(f"{now_s()} {level.upper()} {msg}", flush=True)


def mask(value: str) -> str:
    value = str(value or "")
    if len(value) <= 6:
        return "***" if value else ""
    return value[:3] + "***" + value[-3:]


def read_options() -> dict[str, Any]:
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as fh:
            opts = json.load(fh) or {}
            return opts if isinstance(opts, dict) else {}
    except Exception:
        return {}


def opt(opts: dict[str, Any], key: str, default: Any = "") -> Any:
    value = opts.get(key, default)
    return default if value is None else value


def bool_opt(opts: dict[str, Any], key: str, default: bool = False) -> bool:
    value = opt(opts, key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "on", "yes", "y")


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def escape_frame(frame: bytes) -> bytes:
    out = bytearray(frame)
    i = 2
    while i < len(out) - 1:
        if out[i] == 0xAA and out[i + 1] in (0xAA, 0x55):
            out.insert(i + 1, 0x55)
            i += 1
        i += 1
    return bytes(out)


def encode_cmd(cmd: int, packet_id: int, payload: bytes = b"") -> bytes:
    body_len = len(payload) + 5
    frame = bytearray()
    frame += b"\xAA\xAA"
    frame += body_len.to_bytes(2, "big")
    frame += b"\x00"
    frame += int(packet_id & 0xFFFF).to_bytes(2, "big")
    frame += int(cmd & 0xFFFF).to_bytes(2, "big")
    frame += payload
    frame[4] = checksum(frame[5:])
    return escape_frame(bytes(frame))


def _frame_dict(frame: bytes, body_len: int) -> dict[str, Any]:
    return {
        "raw": frame,
        "len": body_len,
        "checksum_ok": checksum(frame[5:]) == frame[4],
        "packet_id": int.from_bytes(frame[5:7], "big"),
        "cmd": int.from_bytes(frame[7:9], "big"),
        "payload": frame[9:],
    }


def _read_escaped_frame(buf: bytes, start: int):
    out = bytearray()
    i = start
    expected_len = None
    body_len = None
    while i < len(buf):
        out.append(buf[i])
        if len(out) == 4:
            body_len = int.from_bytes(out[2:4], "big")
            if body_len < 5:
                return None, start + 1, False
            expected_len = 4 + body_len
        if expected_len is not None and len(out) >= expected_len:
            return _frame_dict(bytes(out[:expected_len]), int(body_len)), i + 1, False
        if len(out) > 2 and buf[i] == 0xAA and i + 1 < len(buf) and buf[i + 1] == 0x55:
            if i + 2 >= len(buf):
                return None, start, True
            if buf[i + 2] in (0xAA, 0x55):
                i += 1
        i += 1
    return None, start, True


def extract_frames(buf: bytes):
    frames = []
    pos = 0
    while pos < len(buf):
        start = buf.find(b"\xAA\xAA", pos)
        if start < 0:
            return frames, (b"\xAA" if buf.endswith(b"\xAA") else b"")
        if len(buf) - start < 9:
            return frames, buf[start:]
        frame, raw_end, incomplete = _read_escaped_frame(buf, start)
        if incomplete:
            return frames, buf[start:]
        if frame is None:
            pos = raw_end
            continue
        frames.append(frame)
        pos = raw_end
    return frames, b""


def recv_some(sock: socket.socket, seconds: float, quiet_after_data: float = 0.12) -> bytes:
    sock.setblocking(False)
    end = time.time() + max(0.0, float(seconds))
    chunks = []
    last_data = None
    try:
        while time.time() < end:
            try:
                chunk = sock.recv(4096)
                if chunk:
                    chunks.append(chunk)
                    last_data = time.time()
                    continue
                break
            except BlockingIOError:
                if last_data is not None and (time.time() - last_data) >= quiet_after_data:
                    break
                time.sleep(0.02)
            except socket.timeout:
                break
    finally:
        sock.setblocking(True)
    return b"".join(chunks)


def pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data.endswith(bytes([n]) * n):
        return data[:-n]
    return data


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))


def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))


def tlv_bytes(tag_id: int, tag_type: int, value: bytes) -> bytes:
    return ((tag_id << 3) | (tag_type & 7)).to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def ttlv_number(tag_id: int, value: int) -> bytes:
    raw = int(value).to_bytes((int(value).bit_length() + 7) // 8 or 1, "big")
    encoded = bytes([len(raw) - 1]) + raw
    return ((tag_id << 3) | 2).to_bytes(2, "big") + encoded


def ttlv_bool(tag_id: int, value: bool) -> bytes:
    return ((tag_id << 3) | (1 if value else 0)).to_bytes(2, "big")


def parse_random(payload: bytes) -> str:
    if payload[:2] != b"\x00\x0b":
        raise ValueError("unexpected nonce payload")
    size = int.from_bytes(payload[2:4], "big")
    return payload[4:4 + size].decode("ascii")


def normalize_key_to_hex(value: Any) -> str:
    s = str(value or "").strip().replace(" ", "")
    if not s:
        return ""
    if len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
            if len(raw) in (16, 24, 32):
                return raw.hex()
        except Exception:
            pass
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) in (16, 24, 32):
            return raw.hex()
    except Exception:
        pass
    return ""


def load_platforms() -> dict[str, dict[str, str]]:
    with open(PLATFORMS_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh) or {}
    return data if isinstance(data, dict) else {}


def rand_str(n: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def make_cloud_pwd(password: str, rnd: str) -> str:
    md5hex = hashlib.md5(rnd.encode()).hexdigest()
    mid = md5hex[8:24]
    key = mid.upper().encode("ascii")
    iv = (mid[8:16] + mid[0:8]).upper().encode("ascii")
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(password.encode(), 16))
    return base64.b64encode(ct).decode("ascii")


def make_cloud_sig(email: str, pwd_b64: str, rnd: str, secret_suffix: str) -> str:
    return hashlib.sha256(f"{email}{pwd_b64}{rnd}{secret_suffix}".encode()).hexdigest()


def cloud_headers(app_id: str = "584", app_version: str = "3.3.1") -> dict[str, str]:
    return {
        "appVersion": app_version,
        "appSystemType": "android",
        "appId": app_id,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }


def normalize_auth(token: str) -> str:
    token = str(token or "").strip()
    return token if token.lower().startswith("bearer ") else f"Bearer {token}"


def cloud_login(base_url: str, secret_suffix: str, email: str, password: str, domain: str) -> str:
    rnd = rand_str(16)
    pwd_b64 = make_cloud_pwd(password, rnd)
    sig = make_cloud_sig(email, pwd_b64, rnd, secret_suffix)
    data = {
        "email": email,
        "pwd": pwd_b64,
        "random": rnd,
        "userDomain": domain,
        "signature": sig,
    }
    url = base_url.rstrip("/") + "/v2/enduser/enduserapi/emailPwdLogin"
    r = requests.post(url, data=data, headers=cloud_headers(), timeout=15)
    j = r.json()
    if j.get("code") != 200:
        raise RuntimeError(f"cloud login rejected: code={j.get('code')} msg={j.get('msg', '')}")
    d = j.get("data") or {}
    at = d.get("accessToken") or {}
    token = at.get("token") if isinstance(at, dict) else str(at or d.get("token") or "")
    if not token:
        raise RuntimeError("cloud login ok but token missing")
    return token


def parse_device(dev: dict[str, Any]) -> tuple[str, str]:
    dk = str(dev.get("deviceKey") or dev.get("dk") or dev.get("device_key") or "").strip()
    pk = str(dev.get("productKey") or dev.get("pk") or dev.get("product_key") or "").strip()
    return dk, pk


def get_cloud_devices(base_url: str, token: str) -> list[dict[str, Any]]:
    paths = [
        "/v2/binding/enduserapi/userDeviceList",
        "/v2/binding/enduserapi/getBindingList",
        "/v2/binding/enduserapi/getUserBindingList",
        "/v2/binding/enduserapi/getDeviceList",
    ]
    params_list = [
        {"pageSize": 50, "isAssociated": 1},
        {"pageSize": 50, "isAssociated": "true"},
        {"pageSize": 50},
        {},
    ]
    headers = {**cloud_headers(), "Authorization": normalize_auth(token)}
    for path in paths:
        for params in params_list:
            r = requests.get(base_url.rstrip("/") + path, params=params, headers=headers, timeout=12)
            try:
                j = r.json()
            except Exception:
                continue
            if j.get("code") != 200:
                continue
            items: Any = j.get("data") or []
            if isinstance(items, dict):
                items = items.get("list") or items.get("records") or items.get("data") or []
            if not isinstance(items, list):
                continue
            devices = [d for d in items if isinstance(d, dict) and all(parse_device(d))]
            if devices:
                return devices
    return []


def jwt_payload(token: str) -> dict[str, Any]:
    try:
        token = str(token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def jwt_exp(token: str) -> int:
    try:
        exp = int(jwt_payload(token).get("exp") or 0)
        return exp if exp > 0 else 0
    except Exception:
        return 0


def jwt_user_id(token: str) -> str:
    data = jwt_payload(token)
    for key in ("uid", "userId", "user_id", "id"):
        value = data.get(key)
        if value and str(value) != "subject":
            return str(value)
    return ""


def get_cloud_user_info(base_url: str, token: str) -> dict[str, Any]:
    headers = {**cloud_headers(), "Authorization": normalize_auth(token)}
    try:
        r = requests.get(base_url.rstrip("/") + "/v2/enduser/enduserapi/userInfo", headers=headers, timeout=8)
        j = r.json()
        if j.get("code") == 200 and isinstance(j.get("data"), dict):
            return j.get("data") or {}
    except Exception:
        pass
    return {}


def derive_accel_client(domain: str, user_id: str) -> str:
    user_id = str(user_id or "").strip()
    if not user_id:
        return ""
    if user_id[0].isdigit():
        domain_prefix = str(domain or "U")[:1].upper()
        if not domain_prefix.isalpha():
            domain_prefix = "U"
        user_id = f"{domain_prefix}{user_id}"
    return f"qu_{user_id}_"


def discover_accel_client(base_url: str, token: str, domain: str) -> str:
    info = get_cloud_user_info(base_url, token)
    user_id = ""
    for key in ("uid", "userId", "id", "user_id"):
        if info.get(key):
            user_id = str(info.get(key))
            break
    if not user_id:
        user_id = jwt_user_id(token)
    return derive_accel_client(domain, user_id)


def socket_online_flag(dev: dict[str, Any]) -> bool:
    if "onlineStatus" in dev:
        return boolish(dev.get("onlineStatus"))
    status_text = str(dev.get("deviceStatus") or "").strip()
    if status_text:
        return status_text not in ("离线", "offline", "Offline", "OFFLINE")
    return boolish(dev.get("status"))


def extract_smart_socket_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dev in devices or []:
        if not isinstance(dev, dict):
            continue
        dk, pk = parse_device(dev)
        if not dk or pk.lower() not in SMART_SOCKET_PRODUCT_KEYS or dk in seen:
            continue
        seen.add(dk)
        out.append({
            "device_key": dk,
            "product_key": pk,
            "name": str(dev.get("deviceName") or dev.get("name") or dk),
            "product_name": str(dev.get("productName") or "Smart socket"),
            # onlineStatus e' l'unico campo che dice davvero se la presa e'
            # connessa (1 online, 0 offline, e deviceStatus lo ripete a parole).
            # Il vecchio "onlineStatus or status" lo annullava: `status` vale 1
            # anche su una presa staccata dalla corrente, perche' e' lo stato di
            # abbinamento all'account, non di connessione. Risultato: una presa
            # scollegata restava "online" in HA con i valori dell'ultima lettura.
            "online": socket_online_flag(dev),
        })
    return out


def manual_smart_socket_devices(opts: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx in (1, 2):
        dk = str(opt(opts, f"smart_socket_{idx}_device_key", "") or "").strip()
        pk = str(opt(opts, f"smart_socket_{idx}_product_key", "") or "").strip()
        name = str(opt(opts, f"smart_socket_{idx}_name", "") or "").strip()
        if not dk or pk.lower() not in SMART_SOCKET_PRODUCT_KEYS or dk in seen:
            continue
        seen.add(dk)
        out.append({
            "device_key": dk,
            "product_key": pk,
            "name": name or dk,
            "product_name": "Smart socket",
            "online": True,
        })
    return out


def load_host_cache() -> tuple[str, int]:
    try:
        with open(HOST_CACHE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
        host = str(data.get("host") or "").strip()
        port = int(data.get("port") or DEFAULT_CONTROL_PORT)
        return host, port
    except Exception:
        return "", DEFAULT_CONTROL_PORT


def save_host_cache(host: str, port: int) -> None:
    host = str(host or "").strip()
    if not host:
        return
    try:
        os.makedirs(os.path.dirname(HOST_CACHE_PATH), exist_ok=True)
        tmp = f"{HOST_CACHE_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"host": host, "port": int(port), "saved_at": int(time.time())}, fh)
        os.replace(tmp, HOST_CACHE_PATH)
    except Exception as exc:
        log(f"LAN host cache write failed: {exc}", "debug")


class SmartSocketCloud:
    def __init__(self, opts: dict[str, Any]):
        self.opts = opts
        self.email = str(opt(opts, "wf_email", "") or "").strip().lower()
        self.password = str(opt(opts, "wf_password", "") or "")
        self.app = str(opt(opts, "app", "wonderfree") or "wonderfree").strip().lower()
        platform = load_platforms().get(self.app) or {}
        self.base_url = str(platform.get("base_url") or "").rstrip("/")
        self.accel_url = str(platform.get("accel_url") or "").strip()
        self.accel_client = str(platform.get("accel_client") or "").strip()
        self.domain = str(platform.get("wf_domain") or "")
        self.secret = str(platform.get("secret_suffix") or "")
        self.token = ""
        self.exp = 0
        self.lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.email and self.password and self.base_url and self.domain and self.secret)

    def ensure_token(self, force: bool = False) -> str:
        with self.lock:
            now = int(time.time())
            if not force and self.token and self.exp and now < self.exp - SOCKET_TOKEN_SKEW:
                return self.token
            if not self.available():
                return self.token
            self.token = cloud_login(self.base_url, self.secret, self.email, self.password, self.domain)
            self.exp = jwt_exp(self.token) or (now + SOCKET_TOKEN_FALLBACK_TTL)
            if not self.accel_client:
                self.accel_client = discover_accel_client(self.base_url, self.token, self.domain)
                if self.accel_client:
                    log("smart socket accel client derived")
                else:
                    log("smart socket accel client unavailable, using fallback", "warning")
            log(f"smart socket cloud token refreshed app={self.app}")
            return self.token

    def list_devices(self) -> list[dict[str, Any]] | None:
        if not self.available():
            return []
        for attempt in (1, 2):
            try:
                token = self.ensure_token(force=(attempt == 2))
                return get_cloud_devices(self.base_url, token)
            except Exception as exc:
                if attempt == 2:
                    log(f"smart socket cloud device-list failed: {exc}", "warning")
                    return None
                self.exp = 0
        return None

    def request_json(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        token = self.ensure_token()
        headers = {**cloud_headers(), "Authorization": normalize_auth(token)}
        r = requests.get(self.base_url.rstrip("/") + path, params=params, headers=headers, timeout=10)
        return r.json()


def select_powerstation(devices: list[dict[str, Any]], preferred_dk: str = "") -> dict[str, Any]:
    preferred_dk = str(preferred_dk or "").strip().lower()
    if preferred_dk:
        for dev in devices:
            dk, _pk = parse_device(dev)
            if dk.lower() == preferred_dk:
                return dev
    ranked = []
    for idx, dev in enumerate(devices):
        dk, pk = parse_device(dev)
        name = str(dev.get("deviceName") or dev.get("name") or "").lower()
        score = 0
        if pk.lower() in POWERSTATION_PRODUCT_KEYS:
            score += 100
        if any(x in name for x in ("fppt", "t2400", "powerstation", "power station")):
            score += 20
        if "socket" in name or "presa" in name or pk.lower() == "p11spk":
            score -= 100
        if dk:
            score += 1
        ranked.append((score, -idx, dev))
    ranked.sort(reverse=True, key=lambda x: (x[0], x[1]))
    return ranked[0][2] if ranked else {}


def extract_lan_key_hex(dev: Any) -> str:
    if not isinstance(dev, dict):
        return ""
    for key in ("authKey", "authkey", "bindingkey", "bindingKey"):
        found = normalize_key_to_hex(dev.get(key))
        if found:
            return found
    return ""


def deep_find_lan_key_hex(obj: Any) -> str:
    if isinstance(obj, dict):
        direct = extract_lan_key_hex(obj)
        if direct:
            return direct
        for value in obj.values():
            found = deep_find_lan_key_hex(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = deep_find_lan_key_hex(value)
            if found:
                return found
    return ""


def _cloud_get_json(base_url: str, token: str, path: str, params: dict[str, Any]) -> dict[str, Any]:
    headers = {**cloud_headers(), "Authorization": normalize_auth(token)}
    r = requests.get(base_url.rstrip("/") + path, params=params, headers=headers, timeout=12)
    try:
        j = r.json()
    except Exception as exc:
        raise RuntimeError(f"{path} returned non-json response") from exc
    return j if isinstance(j, dict) else {}


def _extract_tsl_properties(response: dict[str, Any]) -> list[dict[str, Any]] | dict[str, Any]:
    if response.get("code") != 200:
        return []
    data = response.get("data")
    if not isinstance(data, dict):
        return []
    properties = data.get("properties") or data.get("property") or data.get("tsl")
    if isinstance(properties, (list, dict)) and properties:
        return properties
    profile = data.get("profile")
    if isinstance(profile, dict):
        properties = profile.get("properties") or profile.get("property")
        if isinstance(properties, (list, dict)) and properties:
            return properties
    return []


def _write_json_atomic(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def save_tsl_bundle(bundle: dict[str, Any]) -> None:
    _write_json_atomic(TSL_DATA_PATH, bundle)
    try:
        _write_json_atomic(TSL_SHARE_COPY_PATH, bundle)
    except Exception as exc:
        log(f"TSL share copy failed: {exc}", "debug")


def refresh_tsl_from_cloud(base_url: str, token: str, dk: str, pk: str) -> bool:
    pk = str(pk or "").strip()
    dk = str(dk or "").strip()
    if not pk:
        return False

    raw_responses: list[dict[str, Any]] = []
    product_response: dict[str, Any] | None = None
    for path, params in (
        ("/v2/binding/enduserapi/productTSL", {"pk": pk}),
        ("/v2/binding/enduserapi/getProductTSL", {"pk": pk}),
        ("/v2/binding/enduserapi/getProductTSL", {"productKey": pk}),
    ):
        try:
            response = _cloud_get_json(base_url, token, path, params)
        except Exception as exc:
            raw_responses.append({"endpoint": path, "params": params, "error": str(exc)})
            continue
        raw_responses.append({"endpoint": path, "params": params, "response": response})
        if _extract_tsl_properties(response):
            product_response = response
            break

    if not product_response:
        raise RuntimeError("product TSL not found in cloud response")

    properties = _extract_tsl_properties(product_response)
    if not properties:
        raise RuntimeError("product TSL has no properties")

    if dk:
        for params in ({"dk": dk, "pk": pk}, {"deviceKey": dk, "productKey": pk}):
            try:
                response = _cloud_get_json(base_url, token, "/v2/binding/enduserapi/getDeviceBusinessAttributes", params)
                raw_responses.append({
                    "endpoint": "/v2/binding/enduserapi/getDeviceBusinessAttributes",
                    "params": params,
                    "response": response,
                })
                break
            except Exception as exc:
                raw_responses.append({
                    "endpoint": "/v2/binding/enduserapi/getDeviceBusinessAttributes",
                    "params": params,
                    "error": str(exc),
                })

    bundle = {
        "parser_version": 8,
        "product_key": pk,
        "device_key": dk,
        "fetched_at": int(time.time()),
        "properties": properties,
        "raw_responses": raw_responses,
    }
    save_tsl_bundle(bundle)
    count = len(properties) if isinstance(properties, list) else len(properties.keys())
    log(f"TSL refreshed from cloud pk={pk} properties={count} saved={TSL_DATA_PATH}")
    return True


def load_lan_key_cache(preferred_dk: str = "") -> tuple[str, str, str] | None:
    try:
        with open(KEY_CACHE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
        if not isinstance(data, dict):
            return None
        dk = str(data.get("device_key") or "").strip()
        pk = str(data.get("product_key") or "").strip()
        key_hex = normalize_key_to_hex(data.get("lan_key_hex"))
        if not key_hex:
            return None
        if preferred_dk and dk and preferred_dk != dk:
            log(f"cached LAN key ignored: cached dk={dk} does not match configured dk={preferred_dk}", "warning")
            return None
        dk = dk or preferred_dk
        pk = pk or "p11tpn"
        return key_hex, dk, pk
    except Exception:
        return None


def fetch_lan_key_from_cloud_live(opts: dict[str, Any]) -> tuple[str, str, str]:
    email = str(opt(opts, "wf_email", "")).strip().lower()
    password = str(opt(opts, "wf_password", ""))
    app = str(opt(opts, "app", "wonderfree")).strip().lower()
    preferred_dk = str(opt(opts, "device_key", "")).strip()
    if not email or not password:
        raise RuntimeError("wf_email/wf_password missing: cloud login is required to recover LAN key")
    platforms = load_platforms()
    platform = platforms.get(app)
    if not platform:
        raise RuntimeError(f"unknown app platform: {app}")
    base_url = str(platform["base_url"]).rstrip("/")
    domain = str(platform["wf_domain"])
    secret = str(platform["secret_suffix"])
    log(f"cloud login using addon method: app={app} base={base_url} domain={domain}")
    token = cloud_login(base_url, secret, email, password, domain)
    devices = get_cloud_devices(base_url, token)
    if not devices:
        raise RuntimeError("cloud device list is empty")
    selected = select_powerstation(devices, preferred_dk)
    dk, pk = parse_device(selected)
    if not dk or not pk:
        raise RuntimeError("no powerstation selected from cloud list")
    key_hex = extract_lan_key_hex(selected)
    source = "userDeviceList"
    if not key_hex:
        headers = {**cloud_headers(), "Authorization": normalize_auth(token)}
        paths = [
            "/v2/binding/enduserapi/getDeviceBusinessAttributes",
            "/v2/binding/enduserapi/getDeviceInfo",
            "/v2/binding/enduserapi/deviceInfo",
            "/v2/binding/enduserapi/getBindingDetail",
            "/v2/binding/enduserapi/getBindingInfo",
        ]
        params_list = [
            {"dk": dk, "pk": pk},
            {"deviceKey": dk, "productKey": pk},
            {"deviceKey": dk},
            {"dk": dk},
            {"pk": pk},
            {},
        ]
        for path in paths:
            for params in params_list:
                r = requests.get(base_url + path, params=params, headers=headers, timeout=10)
                try:
                    j = r.json()
                except Exception:
                    continue
                if j.get("code") != 200:
                    continue
                key_hex = deep_find_lan_key_hex(j.get("data"))
                if key_hex:
                    source = path
                    break
            if key_hex:
                break
    if not key_hex:
        raise RuntimeError("LAN key not found in cloud response")
    try:
        refresh_tsl_from_cloud(base_url, token, dk, pk)
    except Exception as exc:
        log(f"TSL cloud refresh failed: {exc}; using cached TSL if available", "warning")
    with open(KEY_CACHE_PATH, "w", encoding="utf-8") as fh:
        json.dump({"device_key": dk, "product_key": pk, "lan_key_hex": key_hex, "saved_at": int(time.time())}, fh)
    log(f"LAN key recovered from cloud ({source}) for pk={pk} dk={dk}")
    return key_hex, dk, pk


def fetch_lan_key_from_cloud(opts: dict[str, Any]) -> tuple[str, str, str]:
    preferred_dk = str(opt(opts, "device_key", "")).strip()
    cached = load_lan_key_cache(preferred_dk)
    try:
        return fetch_lan_key_from_cloud_live(opts)
    except Exception as exc:
        if cached:
            _key_hex, dk, pk = cached
            log(f"cloud LAN key refresh failed: {exc}; using cached LAN key for pk={pk} dk={dk}", "warning")
            return cached
        raise


def parse_discovery_payload(payload: bytes) -> dict[int, Any]:
    fields, _pos = parse_ttlv_fields(payload, 0, len(payload), None)
    return {field["tag"]: field["value"] for field in fields}


def local_ipv4_guess() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            host = probe.getsockname()[0]
    except Exception:
        return ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if ip.version != 4 or ip.is_loopback or ip.is_link_local:
        return ""
    return str(ip)


def cidr_from_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return ""
    if ip.version != 4 or ip.is_loopback or ip.is_link_local:
        return ""
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def normalized_cidr(cidr: str) -> str:
    cidr = str(cidr or "").strip()
    if not cidr:
        return ""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return cidr
    if network.version != 4:
        return ""
    return str(network)


def host_matches_any_cidr(host: str, cidrs: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return False
    valid_network_seen = False
    for cidr in cidrs:
        cidr = normalized_cidr(cidr)
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        valid_network_seen = True
        if ip in network:
            return True
    return not valid_network_seen


def add_udp_scan_targets(targets: list[str], cidr: str, remaining_hosts: int) -> int:
    cidr = str(cidr or "").strip()
    if not cidr or remaining_hosts <= 0:
        return remaining_hosts
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception as exc:
        log(f"bad udp_scan_cidr={cidr}: {exc}", "warning")
        return remaining_hosts
    if network.version != 4:
        return remaining_hosts
    targets.append(str(network.broadcast_address))
    added = 0
    for ip in network.hosts():
        if added >= remaining_hosts:
            log(f"udp_scan_cidr={cidr} truncated to {MAX_UDP_SCAN_HOSTS} hosts", "warning")
            break
        targets.append(str(ip))
        added += 1
    return max(0, remaining_hosts - added)


def udp_discover(opts: dict[str, Any], expected_dk: str = "") -> tuple[str, int, str, str]:
    configured_host = str(opt(opts, "device_host", "")).strip()
    configured_port = int(opt(opts, "device_port", DEFAULT_CONTROL_PORT) or DEFAULT_CONTROL_PORT)
    scan_cidr = str(opt(opts, "udp_scan_cidr", "")).strip()
    targets: list[str] = []
    if configured_host:
        targets.append(configured_host)
    targets.append("255.255.255.255")
    remaining_hosts = MAX_UDP_SCAN_HOSTS
    seen_cidrs: set[str] = set()
    scan_cidrs = (scan_cidr, cidr_from_host(configured_host), cidr_from_host(local_ipv4_guess()))
    for cidr in scan_cidrs:
        cidr = normalized_cidr(cidr)
        if not cidr or cidr in seen_cidrs:
            continue
        seen_cidrs.add(cidr)
        remaining_hosts = add_udp_scan_targets(targets, cidr, remaining_hosts)
    seen = set()
    targets = [x for x in targets if not (x in seen or seen.add(x))]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.06)
    frame = encode_cmd(CMD_DISCOVERY_PROBE, 1)
    for host in targets:
        try:
            sock.sendto(frame, (host, DISCOVERY_PORT))
        except OSError:
            pass
        if host != "255.255.255.255":
            time.sleep(0.002)
    replies = []
    end = time.time() + 3.0
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError as exc:
            log(f"UDP discovery receive ignored: {exc}", "debug")
            continue
        frames, _tail = extract_frames(data)
        for frame_info in frames:
            if frame_info.get("cmd") != CMD_DISCOVERY_REPLY:
                continue
            info = parse_discovery_payload(frame_info.get("payload", b""))
            pk = str(info.get(3, ""))
            dk = str(info.get(4, ""))
            ip = str(info.get(5, addr[0]))
            port = int(info.get(6, configured_port) or configured_port)
            replies.append((ip, port, dk, pk))
    sock.close()
    if expected_dk:
        for reply in replies:
            if reply[2].lower() == expected_dk.lower():
                log(f"UDP discovery matched dk={reply[2]} ip={reply[0]} port={reply[1]} pk={reply[3]}")
                return reply
    if replies:
        reply = replies[0]
        log(f"UDP discovery found dk={reply[2]} ip={reply[0]} port={reply[1]} pk={reply[3]}")
        return reply
    if configured_host:
        log(f"UDP discovery no reply, using configured host {configured_host}:{configured_port}", "warning")
        return configured_host, configured_port, expected_dk, ""
    raise RuntimeError("UDP discovery failed: set device_host or udp_scan_cidr")


def connect_and_login(host: str, port: int, key_hex: str, timeout: float = 6.0):
    key = bytes.fromhex(key_hex)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(encode_cmd(CMD_HELLO, 1))
        data = recv_some(sock, timeout)
        nonce = None
        frames, _tail = extract_frames(data)
        for frame in frames:
            if frame["cmd"] == CMD_NONCE:
                nonce = parse_random(frame["payload"])
        if not nonce:
            raise RuntimeError("no nonce from device")
        digest = hashlib.sha256((key.hex() + ";" + nonce).encode("utf-8")).hexdigest().encode("ascii")
        sock.sendall(encode_cmd(CMD_LOGIN, 1, tlv_bytes(2, 3, digest)))
        data = recv_some(sock, timeout)
        status = None
        frames, _tail = extract_frames(data)
        for frame in frames:
            if frame["cmd"] != CMD_LOGIN_RESULT:
                continue
            payload = frame["payload"]
            if payload.endswith(b"\x00\x00"):
                status = 0
            elif payload.endswith(b"\x00\x02"):
                status = 2
            else:
                status = payload.hex()
        if status not in (0, 2):
            raise RuntimeError(f"login rejected: {status}")
        return sock, key, nonce.encode("ascii"), status
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def read_number(data: bytes, pos: int, end: int) -> tuple[int | float, int]:
    if pos >= end:
        raise ValueError("number prefix missing")
    prefix = data[pos]
    pos += 1
    decimals = (prefix >> 3) & 0x0F
    nbytes = (prefix & 0x07) + 1
    if pos + nbytes > end:
        raise ValueError("number truncated")
    value = int.from_bytes(data[pos:pos + nbytes], "big")
    pos += nbytes
    if prefix & 0x80:
        value = -value
    if decimals:
        return value / (10 ** decimals), pos
    return value, pos


def parse_ttlv_fields(data: bytes, pos: int = 0, end: int | None = None, count: int | None = None):
    end = len(data) if end is None else end
    fields = []
    parsed = 0
    while pos + 2 <= end and (count is None or parsed < count):
        header = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        tag = header >> 3
        typ = header & 7
        if typ in (0, 1):
            value = bool(typ)
        elif typ == 2:
            value, pos = read_number(data, pos, end)
        elif typ in (3, 5):
            if pos + 2 > end:
                raise ValueError("string length truncated")
            size = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            if pos + size > end:
                raise ValueError("string truncated")
            raw = data[pos:pos + size]
            pos += size
            try:
                value = raw.decode("utf-8")
            except Exception:
                value = raw.hex()
        elif typ == 4:
            if pos + 2 > end:
                raise ValueError("struct count truncated")
            child_count = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            value, pos = parse_ttlv_fields(data, pos, end, child_count)
        else:
            raise ValueError(f"unsupported ttlv type {typ}")
        fields.append({"tag": tag, "type": typ, "value": value})
        parsed += 1
    return fields, pos


def iter_tsl_items(container: Any):
    if isinstance(container, dict):
        for code, info in container.items():
            if isinstance(info, dict):
                yield str(code), info
    elif isinstance(container, list):
        for item in container:
            if isinstance(item, dict):
                code = item.get("code") or item.get("identifier") or item.get("identifierName") or item.get("name")
                yield str(code or ""), item


def first_value(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", []):
            return value
    return None


def load_tsl_bundle() -> dict[str, Any]:
    for path in TSL_PATHS:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            continue
    return {}


def load_tsl_schema() -> tuple[dict[int, dict[str, Any]], list[int]]:
    bundle = load_tsl_bundle()
    top: dict[int, dict[str, Any]] = {}

    def parse_item(code_hint: str, info: dict[str, Any]) -> dict[str, Any] | None:
        raw_id = first_value(info, ("id", "abId", "abid", "resourceId", "attributeId", "attrId", "paramId"))
        try:
            ident = int(raw_id)
        except Exception:
            return None
        code = str(first_value(info, ("code", "resourceCode", "identifier", "identifierName", "name")) or code_hint or f"id_{ident}")
        typ = str(first_value(info, ("dataType", "type", "valueType")) or "").upper()
        specs = info.get("specs") or info.get("define") or info.get("schema") or {}
        children: dict[int, dict[str, Any]] = {}
        child_list = []
        if isinstance(specs, list):
            child_list = specs
        elif isinstance(specs, dict):
            if isinstance(specs.get("specs"), list):
                child_list = specs.get("specs") or []
        for child in child_list:
            if not isinstance(child, dict):
                continue
            child_code = str(child.get("code") or child.get("identifier") or child.get("name") or "")
            parsed = parse_item(child_code, child)
            if parsed:
                children[int(parsed["id"])] = parsed
        return {"id": ident, "code": code, "type": typ, "specs": specs, "children": children}

    for section in ("properties", "controls", "tsl_controls"):
        for code, info in iter_tsl_items(bundle.get(section)):
            parsed = parse_item(code, info)
            if parsed:
                top[int(parsed["id"])] = parsed
    ids = sorted(i for i in top if 0 < i <= 0xFFFF and i not in READ_EXCLUDED_IDS)
    if not ids:
        ids = list(P11TPN_FALLBACK_READ_IDS)
    return top, ids


def _actual_type(info: dict[str, Any]) -> str:
    raw = str(info.get("dataType") or info.get("valueType") or info.get("type") or "").upper()
    if raw in ("PROPERTY", "FUNCTION", "EVENT"):
        raw = str(info.get("type") or "").upper()
    return raw


def _is_writable(info: dict[str, Any]) -> bool:
    if info.get("writable") is True:
        return True
    if info.get("writable") is False:
        return False
    access = str(info.get("access") or info.get("subType") or "").upper()
    return "W" in access


def _spec_items(specs: Any) -> list[dict[str, Any]]:
    if isinstance(specs, list):
        return [x for x in specs if isinstance(x, dict)]
    if isinstance(specs, dict) and isinstance(specs.get("specs"), list):
        return [x for x in specs.get("specs") or [] if isinstance(x, dict)]
    return []


def enum_options(specs: Any) -> dict[int, str]:
    out: dict[int, str] = {}
    used: set[str] = set()
    for item in _spec_items(specs):
        value = item.get("value", item.get("val"))
        label = item.get("displayName") or item.get("name") or item.get("label")
        if value is None or label is None:
            continue
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            continue
        text = str(label)
        if text in used:
            text = f"{text} ({ivalue})"
        used.add(text)
        out[ivalue] = text
    return out


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def number_bounds(specs: Any) -> tuple[float | None, float | None, float | None, str | None]:
    if not isinstance(specs, dict):
        return None, None, None, None
    lo = _float_or_none(specs.get("min"))
    hi = _float_or_none(specs.get("max"))
    step = _float_or_none(specs.get("step")) or 1.0
    unit = specs.get("unit")
    unit = str(unit) if unit not in (None, "") else None
    return lo, hi, step, unit


def clean_number(value: float | None) -> int | float | None:
    if value is None:
        return None
    return int(value) if float(value).is_integer() else value


def build_control_catalogs() -> dict[str, dict[str, Any]]:
    bundle = load_tsl_bundle()
    catalog = bundle.get("properties") or bundle.get("controls") or {}
    controls: dict[str, dict[str, Any]] = {}
    for code, info in iter_tsl_items(catalog):
        if not isinstance(info, dict):
            continue
        code = str(first_value(info, ("code", "resourceCode", "identifier", "identifierName", "name")) or code)
        if not code or code in HIDDEN_CONTROL_CODES or not _is_writable(info):
            continue
        raw_id = first_value(info, ("id", "abId", "abid", "resourceId", "attributeId", "attrId", "paramId"))
        try:
            ident = int(raw_id)
        except Exception:
            continue
        typ = _actual_type(info)
        specs = info.get("specs") or info.get("define") or info.get("schema") or {}
        name = str(info.get("name") or code)
        entry: dict[str, Any] = {"code": code, "name": name, "id": ident, "type": typ}
        if typ == "BOOL":
            entry["kind"] = "switch"
            controls[code] = entry
        elif typ == "ENUM":
            options = enum_options(specs)
            if options:
                entry["options"] = options
                if code in ENUM_AS_SWITCH:
                    entry["kind"] = "switch"
                    entry["on_value"] = ENUM_AS_SWITCH[code]
                else:
                    entry["kind"] = "select"
                controls[code] = entry
        elif typ in ("INT", "INTEGER", "LONG", "UINT", "UINT16", "UINT32", "FLOAT", "DOUBLE"):
            lo, hi, step, unit = number_bounds(specs)
            entry.update({"kind": "number", "min": clean_number(lo), "max": clean_number(hi),
                          "step": clean_number(step), "unit": unit})
            controls[code] = entry
    return controls


def spec_scale(info: dict[str, Any]) -> float:
    specs = info.get("specs") if isinstance(info, dict) else {}
    step = ""
    if isinstance(specs, dict):
        step = str(specs.get("step") or "")
    if step in ("0.1", ".1"):
        return 0.1
    if step in ("0.01", ".01"):
        return 0.01
    if step in ("0.001", ".001"):
        return 0.001
    return 1.0


NO_SCALE_CODES = {"pv_1_voltage"}


def apply_scale(value: Any, info: dict[str, Any]) -> Any:
    if isinstance(value, (int, float)):
        code = str(info.get("code") or "") if isinstance(info, dict) else ""
        if code in NO_SCALE_CODES:
            return value
        scale = spec_scale(info)
        if scale != 1.0:
            return round(float(value) * scale, 3)
    return value


def flatten_struct(fields: list[dict[str, Any]], children: dict[int, dict[str, Any]], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        tag = int(field["tag"])
        info = children.get(tag, {"code": f"{prefix}field_{tag}", "children": {}, "specs": {}})
        code = str(info.get("code") or f"{prefix}field_{tag}")
        value = field["value"]
        if isinstance(value, list):
            nested_children = info.get("children") or {}
            if tag == 0:
                out.update(flatten_struct(value, children, prefix))
            else:
                nested = flatten_struct(value, nested_children, code + "_")
                out.update(nested)
        else:
            out[code] = apply_scale(value, info)
    return out


def decode_payload(plain: bytes, schema: dict[int, dict[str, Any]]) -> dict[str, Any]:
    fields, _pos = parse_ttlv_fields(plain, 0, len(plain), None)
    out: dict[str, Any] = {}
    for field in fields:
        tag = int(field["tag"])
        info = schema.get(tag, {"code": f"id_{tag}", "children": {}, "specs": {}})
        code = str(info.get("code") or f"id_{tag}")
        value = field["value"]
        if isinstance(value, list):
            out.update(flatten_struct(value, info.get("children") or {}, code + "_"))
        else:
            out[code] = apply_scale(value, info)
    apply_aliases(out)
    return out


def enum_label_high_frequency(value: Any) -> str:
    try:
        v = int(value)
    except Exception:
        return str(value)
    return HFR_MODE_LABELS.get(v, str(value))


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _between(value: Any, low: float, high: float) -> bool:
    n = _num(value)
    return n is not None and low <= n <= high


def normalize_pack_voltage(value: Any) -> float | None:
    n = _num(value)
    if n is None:
        return None
    if 40.0 <= n <= 70.0:
        return n
    if 400.0 <= n <= 700.0:
        return n / 10.0
    if 4000.0 <= n <= 7000.0:
        return n / 100.0
    if 4.0 <= n <= 7.0:
        return n * 10.0
    return None


def normalize_grid_voltage(value: Any) -> float | None:
    n = _num(value)
    if n is None:
        return None
    if 150.0 <= n <= 270.0:
        return n
    if 15.0 <= n <= 27.0:
        return n * 10.0
    if 1500.0 <= n <= 2700.0:
        return n / 10.0
    if n == 0:
        return 0.0
    return None


def normalize_temp(value: Any, scaled_tenths: bool = False) -> float | None:
    """Temperatura in gradi.

    `scaled_tenths` va messo sui campi che il TSL dichiara con step 0.1 mentre
    il device manda gradi interi (bms_mos_temp, stessa svista di ac_voltage):
    li' apply_scale ha gia' diviso per 10 e qui si rimette a posto. La finestra
    -5..13 fa da paracadute se un domani il firmware passasse davvero ai
    decimi. Prima questa funzione moltiplicava per 10 qualsiasi valore fra 1 e
    10 a prescindere dal campo: cosi' i 9 gradi veri del BMS uscivano 0,9 e i 5
    gradi di inverter e MPPT uscivano 50.
    """
    n = _num(value)
    if n is None:
        return None
    if scaled_tenths and -5.0 <= n <= 13.0:
        n = n * 10.0
    return n if -40.0 <= n <= 120.0 else None


def normalize_aux_voltage(value: Any) -> float | None:
    n = _num(value)
    if n is None:
        return None
    if n == 0:
        return 0.0
    if 0.1 <= n <= 3.0:
        return n * 10.0
    return n


def label_device_status(value: Any) -> str | None:
    try:
        status = int(float(value))
    except Exception:
        return str(value) if value not in (None, "") else None
    return {
        0: "Standby",
        1: "In carica",
        2: "In scarica",
        3: "Carica e scarica",
        4: "Bypass",
    }.get(status, str(status))


_FAULT_LABELS: dict[int, str] | None = None


def fault_labels_from_tsl() -> dict[int, str]:
    """Etichette ufficiali dei codici guasto, prese dall'enum del TSL.

    Il TSL ne definisce 44 e le scrive a due cifre (E01, E02, E07), mentre
    prima le costruivamo a mano come f"E{code}" ottenendo "E2" invece di
    "E02": un codice che non si ritrova piu' sul manuale.
    """
    global _FAULT_LABELS
    if _FAULT_LABELS is None:
        labels: dict[int, str] = {}
        try:
            for _code, info in iter_tsl_items(load_tsl_bundle().get("properties")):
                if str(info.get("code")) == "fault_code":
                    labels = enum_options(info.get("specs") or info.get("define") or {})
                    break
        except Exception as exc:
            log(f"fault code labels unavailable: {exc}", "debug")
        _FAULT_LABELS = labels
    return _FAULT_LABELS


def fault_label(value: Any) -> str | None:
    try:
        code = int(float(value))
    except Exception:
        return str(value) if value not in (None, "") else None
    if code == 0:
        return "Normale"
    text = fault_labels_from_tsl().get(code)
    if text and text.strip().lower() not in ("normal", "normale"):
        return text
    return f"E{code}"


def derive_device_status(out: dict[str, Any]) -> str | None:
    current = label_device_status(out.get("device_status"))
    battery_power = _num(out.get("battery_total_power"))
    pv_power = abs(_num(out.get("pv_input_power")) or 0.0)
    ac_input = abs(_num(out.get("ac_input_power")) or 0.0)
    output_power = max(
        abs(_num(out.get("total_output_power")) or 0.0),
        abs(_num(out.get("ac_output_power")) or 0.0),
        abs(_num(out.get("grid_b_power")) or 0.0),
        abs(_num(out.get("dc_output_power")) or 0.0),
        abs(_num(out.get("dc_total_power")) or 0.0),
    )
    if battery_power is not None:
        if battery_power <= -50 or (battery_power < -20 and output_power >= 30):
            return "In scarica"
        if battery_power >= 50 or pv_power >= 30 or ac_input >= 30:
            return "In carica"
        if abs(battery_power) < 30 and output_power < 30 and pv_power < 30 and ac_input < 30:
            return "Standby"
    return current


def apply_aliases(out: dict[str, Any]) -> None:
    pack_only = "pack_num" in out and "battery_total_power" not in out and "battery_total_voltage" not in out
    if not pack_only and _between(out.get("soc"), 0, 100):
        out["battery_percentage"] = int(float(out["soc"]))
    remaining = out.get("remaining_time")
    if remaining is None:
        remaining = out.get("battery_data_remaining_time")
    if not pack_only and _between(remaining, 0, REMAINING_TIME_MAX_MINUTES):
        out["remaining_time_minutes"] = int(float(remaining))

    cell_values: list[float] = []
    for idx in range(1, 15):
        src = f"CellVoltage{idx}"
        if src not in out:
            continue
        raw = _num(out[src])
        if raw is None:
            continue
        cell = raw / 1000.0 if raw > 10 else raw
        if 2.5 <= cell <= 4.5:
            out[f"battery_cell_{idx:02d}_voltage"] = round(cell, 3)
            if idx <= 13:
                cell_values.append(cell)

    voltage = normalize_pack_voltage(out.get("battery_total_voltage"))
    if voltage is None and "battery_voltage" in out:
        voltage = normalize_pack_voltage(out.get("battery_voltage"))
    if len(cell_values) >= 13:
        total = round(sum(cell_values[:13]), 1)
        if 40.0 <= total <= 70.0:
            voltage = total
    if voltage is not None:
        out["battery_voltage"] = round(voltage, 1)

    if "battery_total_power" in out:
        out["battery_power"] = out["battery_total_power"]
        power = _num(out["battery_total_power"])
        if power is not None and voltage:
            out["battery_current"] = round(power / voltage, 2)

    if "pv_total_power" in out:
        out["pv_input_power"] = out["pv_total_power"]
    if "pv_1_voltage" in out:
        out["pv_panel_voltage"] = out["pv_1_voltage"]
    if "ac_power" in out:
        out["ac_output_power"] = out["ac_power"]
    if "dc_total_power" in out:
        out["dc_output_power"] = out["dc_total_power"]
    if "ac_voltage" in out:
        ac_v = normalize_grid_voltage(out["ac_voltage"])
        if ac_v is not None:
            out["ac_voltage"] = int(ac_v) if ac_v == int(ac_v) else round(ac_v, 1)
    if "grid_voltage" in out:
        grid_voltage = normalize_grid_voltage(out["grid_voltage"])
        if grid_voltage is not None:
            out["grid_voltage"] = int(grid_voltage) if grid_voltage == int(grid_voltage) else round(grid_voltage, 1)
    if "grid_frequency" in out:
        out["grid_freq"] = out["grid_frequency"]
    for aux_key in (
        "usb_1_voltage", "usb_2_voltage", "usb_3_voltage", "usb_4_voltage",
        "typec_1_voltage", "typec_2_voltage", "dc_12V_voltage", "dc_24V_voltage",
        "dc_12v_voltage", "dc_24v_voltage",
    ):
        if aux_key in out:
            aux_voltage = normalize_aux_voltage(out[aux_key])
            if aux_voltage is not None:
                out[aux_key] = int(aux_voltage) if aux_voltage == int(aux_voltage) else round(aux_voltage, 2)
    # grid_b_power (gruppo TSL grid_data) e' il micro inverter: positivo = spinge
    # in casa, negativo = prende dalla rete per caricare. NON e' l'uscita delle
    # 4 prese AC (quella e' ac_power, gruppo ac_data) e non deve sovrascriverla:
    # i report arrivano in frame separati, quindi un frame "grid" senza ac_data
    # azzerava AC Output Power e Total Output Power.
    if "grid_b_power" in out:
        try:
            grid_power = float(out["grid_b_power"])
            out["ac_input_power"] = int(abs(grid_power)) if grid_power < 0 else 0
        except Exception:
            pass
    pv = float(out.get("pv_input_power") or 0)
    ac_in = float(out.get("ac_input_power") or 0)
    ac_out = float(out.get("ac_output_power") or 0)
    dc_out = float(out.get("dc_total_power") or out.get("dc_output_power") or 0)
    # Il micro inverter che spinge in casa e' uscita a tutti gli effetti: con le
    # prese AC spente era l'unica cosa che erogava e il totale diceva 0.
    grid_out = max(float(out.get("grid_b_power") or 0), 0.0)
    if any(k in out for k in ("pv_input_power", "pv_total_power", "ac_input_power", "total_input_power")):
        out["total_input_power"] = round(pv + ac_in, 1)
    # Solo se in QUESTO frame c'e' davvero un campo di uscita: partire da un frame
    # che non li contiene (es. quello del micro inverter) dava sempre 0.
    if any(k in out for k in ("ac_output_power", "ac_power", "dc_total_power", "dc_output_power", "total_output_power", "grid_b_power")):
        out["total_output_power"] = round(ac_out + dc_out + grid_out, 1)
    if "high_frequency_reporting" in out:
        out["high_frequency_reporting"] = enum_label_high_frequency(out["high_frequency_reporting"])
    if "device_status" in out:
        labelled = label_device_status(out["device_status"])
        if labelled is not None:
            out["device_status"] = labelled
    if "hmi_data_no" in out and isinstance(out["hmi_data_no"], str):
        parts = out["hmi_data_no"].split(",")
        try:
            status = int(parts[0])
            out["device_status_raw"] = status
            if "device_status" not in out:
                out["device_status"] = label_device_status(status)
        except Exception:
            pass
        if len(parts) > 3:
            try:
                fault = int(parts[3])
                out["fault_code_raw"] = fault
                out["fault_code"] = fault_label(fault)
            except Exception:
                pass
    if "fault_code" in out:
        labelled = fault_label(out["fault_code"])
        if labelled is not None:
            out["fault_code"] = labelled
    device_status = derive_device_status(out)
    if device_status:
        out["device_status"] = device_status
    if "output_power_set" in out:
        try:
            val = float(out["output_power_set"])
            if val > 800 and val % 10 == 0:
                val = val / 10.0
            out["output_power_set"] = int(val) if val == int(val) else val
        except Exception:
            pass
    if "bms_mos_temp" in out:
        temp = normalize_temp(out["bms_mos_temp"], scaled_tenths=True)
        if temp is not None:
            out["temp_bms"] = round(temp, 1)
    if "inv_temp_max" in out:
        temp = normalize_temp(out["inv_temp_max"])
        if temp is not None:
            out["temp_inv"] = round(temp, 1)
    if "mppt_temp_max" in out:
        temp = normalize_temp(out["mppt_temp_max"])
        if temp is not None:
            out["temp_mppt"] = round(temp, 1)
    if "BatCycleCnt" in out:
        out["battery_cycles"] = out["BatCycleCnt"]
    if "AllowMaxChgCurr" in out:
        out["bms_allow_max_charge_current"] = out["AllowMaxChgCurr"]
    if "MosStatus" in out:
        out["bms_mos_status"] = out["MosStatus"]


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower())
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "value"


# Doppioni grezzi di valori gia' pubblicati sotto un altro nome: restano fuori.
# I tre dati di salute del pacco (cicli, corrente massima concessa, stato MOS)
# stavano qui pur non duplicando nulla, quindi venivano ricevuti e buttati via:
# ora tornano pubblicati.
LEGACY_SENSOR_CLEANUP_KEYS = {
    "dc_output_power",
    "grid_freq",
    "pv_panel_voltage",
}
HIDDEN_SENSOR_SLUGS = {slugify(key) for key in RAW_DUPLICATE_KEYS | LEGACY_SENSOR_CLEANUP_KEYS}


def should_publish_sensor_key(key: str, control_codes: set[str] | None = None) -> bool:
    slug = slugify(key)
    if slug in HIDDEN_SENSOR_SLUGS:
        return False
    if slug not in PUBLISH_SENSOR_SLUGS:
        return False
    if control_codes and key in control_codes:
        return False
    return True


def prune_decoded_for_cache(decoded: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(decoded)
    # Il frame di risposta alla lettura completa (l'unico che porta mac_set) NON
    # ha il gruppo ac_data valorizzato dal firmware: ac_power torna 0 anche con
    # 2,4 kW veri alle prese. L'uscita AC buona arriva solo nel report spontaneo
    # di ac_data, quindi questi zeri vanno scartati prima di entrare in cache,
    # altrimenti cancellano il valore giusto.
    if "mac_set" in cleaned:
        for key in ("ac_power", "ac_output_power", "total_output_power"):
            cleaned.pop(key, None)
    pack_only = "pack_num" in cleaned and "battery_total_power" not in cleaned and "battery_total_voltage" not in cleaned
    if pack_only:
        for key in ("soc", "battery_percentage", "remaining_time", "remaining_time_minutes"):
            cleaned.pop(key, None)
    if "remaining_time_minutes" in cleaned and not _between(cleaned.get("remaining_time_minutes"), 0, REMAINING_TIME_MAX_MINUTES):
        cleaned.pop("remaining_time_minutes", None)
    if "remaining_time" in cleaned and not _between(cleaned.get("remaining_time"), 0, REMAINING_TIME_MAX_MINUTES):
        cleaned.pop("remaining_time", None)
    return cleaned


def unit_for(key: str) -> str | None:
    k = key.lower()
    if k == "remaining_time_minutes":
        return None
    if k.endswith("_wh") or "_wh_" in k:
        return "Wh"
    if "percentage" in k or k == "soc":
        return "%"
    if "power" in k:
        return "W"
    if "voltage" in k:
        return "V"
    if "current" in k:
        return "A"
    if "temp" in k:
        return "\u00b0C"
    if "frequency" in k or k.endswith("_freq"):
        return "Hz"
    if "time" in k or "minutes" in k:
        return "min"
    if "signal_strength" in k:
        return "dBm"
    return None


def device_class_for(key: str) -> str | None:
    k = key.lower()
    if k == "remaining_time_minutes":
        return None
    if k.endswith("_wh") or "_wh_" in k:
        return "energy"
    if "percentage" in k or k == "soc":
        return "battery"
    if "power" in k:
        return "power"
    if "voltage" in k:
        return "voltage"
    if "current" in k:
        return "current"
    if "temp" in k:
        return "temperature"
    if "frequency" in k or k.endswith("_freq"):
        return "frequency"
    if "signal_strength" in k:
        return "signal_strength"
    return None


def display_precision_for(key: str) -> int | None:
    k = key.lower()
    if k.endswith("_wh") or "_wh_" in k:
        return 0
    if "temp" in k:
        return 0
    if "power" in k:
        return 0
    if "current" in k:
        return 2
    if "voltage" in k:
        if any(token in k for token in ("usb_", "usb_a", "typec_", "dc_12", "dc_24", "dc12v", "dc24v")):
            return 0
        return 3 if "battery_cell" in k else 1
    return None


def format_remaining_time(value: Any) -> str:
    try:
        text = str(value).strip().lower()
        minutes = int(float(text.split("min", 1)[0].strip() if "min" in text else value))
    except Exception:
        return format_state(value)
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


def format_state(value: Any) -> str:
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    text = str(value)
    return text[:250]


def format_sensor_state(key: str, value: Any) -> str:
    if slugify(key) == "remaining_time_minutes":
        return format_remaining_time(value)
    if slugify(key) == "battery_remaining_wh":
        number = _num(value)
        if number is not None:
            return str(int(round(number)))
    if "temp" in slugify(key):
        number = _num(value)
        if number is not None:
            return str(int(number)) if number == int(number) else format_state(round(number, 1))
    return format_state(value)


def has_measurement_state_class(key: str, sample: Any) -> bool:
    slug = slugify(key)
    if slug in ("remaining_time_minutes", "battery_remaining_wh"):
        return False
    return isinstance(sample, (int, float)) and not isinstance(sample, bool)


def compat_sensor_id(key: str) -> str | None:
    slug = slugify(key)
    if slug == "status":
        return None
    if slug in COMPAT_SENSOR_ID_OVERRIDES:
        return COMPAT_SENSOR_ID_OVERRIDES[slug]
    if slug in PUBLISH_SENSOR_SLUGS:
        return slug
    return None


def human_name_for_sensor(key: str) -> str:
    key = slugify(key)
    if key in COMPAT_SENSOR_NAME_OVERRIDES:
        return COMPAT_SENSOR_NAME_OVERRIDES[key]
    parts = []
    for part in key.split("_"):
        if part in ("ac", "dc", "pv", "usb", "bms", "soc"):
            parts.append(part.upper())
        elif part == "typec":
            parts.append("Typec")
        else:
            parts.append(part.capitalize())
    return " ".join(parts)


def update_battery_remaining_wh(cache: dict[str, Any], opts: dict[str, Any]) -> None:
    soc = _num(cache.get("battery_percentage"))
    capacity = _num(opt(opts, "battery_capacity_wh", 2048))
    if soc is None or capacity is None or not (0 <= soc <= 100) or capacity <= 0:
        return
    cache["battery_remaining_wh"] = int(round(capacity * soc / 100.0))


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "on", "yes", "y")


def bool_state(value: Any) -> str:
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    text = str(value).strip().lower()
    if text in ("1", "true", "on", "yes"):
        return "ON"
    return "OFF"


def socket_liveness_topic(base_topic: str) -> str:
    return f"{base_topic}/smart_sockets/bridge_availability"


def smart_socket_bus_topics(socket_dev: dict[str, Any]) -> list[str]:
    pk = str(socket_dev["product_key"])
    dk = str(socket_dev["device_key"])
    return [
        f"q/1/d/qd{pk}{dk}/bus",
        f"q/2/d/qd{pk}{dk}/bus",
        f"q/1/d/qd/{pk}/{dk}/bus",
        f"q/2/d/qd/{pk}/{dk}/bus",
    ]


def smart_socket_frame(seq: int, on: bool) -> bytes:
    raw = SMART_SOCKET_ON_HEX if on else SMART_SOCKET_OFF_HEX
    frame = bytearray(bytes.fromhex(raw.replace(" ", "")))
    if len(frame) >= 7:
        frame[6] = int(seq) & 0xFF
    return bytes(frame)
