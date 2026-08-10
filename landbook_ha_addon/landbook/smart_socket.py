"""landbook.smart_socket — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    DEVICE_NAME,
    DEVICE_OBJECT_ID,
    PLATFORMS_PATH,
    SMART_SOCKET_FALLBACK_DEVICES,
    SMART_SOCKET_NOT_FOUND_LIMIT,
    SMART_SOCKET_OFF_HEX,
    SMART_SOCKET_ON_HEX,
    SMART_SOCKET_PRODUCT_KEYS,
    SMART_SOCKET_SENSOR_DEFS,
    _boolish,
    _command_tx_allowed,
    _dprint,
)

from landbook.cache_store import (
    _device_key,
    _load_discovered_cache,
    _save_discovered_cache,
)


def _socket_cloud():
    """Return the cloud session manager for smart sockets, or None.

    Isolated in wf_socket_cloud so the powerstation LAN path stays untouched:
    this owns the cloud access-token refresh and the live device list.
    """
    try:
        from wf_socket_cloud import get_cloud
    except Exception as exc:
        print(f"[socket-cloud] modulo non disponibile: {exc}", flush=True)
        return None
    return get_cloud()


def _normalize_auth_header(token: str) -> str:
    token = str(token or "").strip()
    if not token:
        return ""
    return token if token.lower().startswith("bearer ") else f"Bearer {token}"


def _cloud_base_url(discovered: dict) -> str:
    base = str(discovered.get("base_url") or "").strip()
    if base:
        return base.rstrip("/")
    platform = str(discovered.get("_platform") or "").strip()
    for path in (PLATFORMS_PATH, os.path.join(os.path.dirname(__file__), "platforms.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                platforms = json.load(fh) or {}
            cfg = platforms.get(platform) or {}
            base = str(cfg.get("base_url") or "").strip()
            if base:
                return base.rstrip("/")
        except Exception:
            pass
    return ""


def _cloud_accel_url(discovered: dict) -> str:
    accel_url = str(discovered.get("accel_url") or "").strip()
    if accel_url:
        return accel_url
    platform = str(discovered.get("_platform") or "").strip()
    for path in (PLATFORMS_PATH, os.path.join(os.path.dirname(__file__), "platforms.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                platforms = json.load(fh) or {}
            cfg = platforms.get(platform) or {}
            accel_url = str(cfg.get("accel_url") or "").strip()
            if accel_url:
                return accel_url
        except Exception:
            pass
    return ""


def _smart_socket_devices(args) -> list:
    if not getattr(args, "smart_sockets_enabled", True):
        return []
    data = _load_discovered_cache()
    devices = data.get("smart_socket_devices") or []
    out = []

    def add_socket(dk: str, pk: str, name: str = "", product_name: str = "Smart socket"):
        dk = str(dk or "").strip()
        pk = str(pk or "").strip()
        if not dk or pk.lower() not in SMART_SOCKET_PRODUCT_KEYS:
            return
        if any(existing["device_key"] == dk for existing in out):
            return
        out.append({
            "device_key": dk,
            "product_key": pk,
            "name": str(name or dk),
            "product_name": str(product_name or "Smart socket"),
        })

    for dev in devices:
        if not isinstance(dev, dict):
            continue
        pk = str(dev.get("product_key") or dev.get("productKey") or "").strip()
        dk = str(dev.get("device_key") or dev.get("deviceKey") or "").strip()
        add_socket(
            dk,
            pk,
            str(dev.get("name") or dev.get("deviceName") or dk),
            str(dev.get("product_name") or dev.get("productName") or "Smart socket"),
        )
    # La lista auto-rilevata dal cloud (smart_socket_devices in cache) è
    # autoritativa: le prese vengono scoperte da sole e, se eliminate dall'app,
    # spariscono. Le chiavi statiche in config e i fallback interni servono solo
    # come rete di sicurezza quando il cloud non ha ancora popolato la cache
    # (primo avvio offline / credenziali assenti) — altrimenti riaggiungerebbero
    # una presa appena rimossa.
    if not out:
        for idx in (1, 2):
            add_socket(
                getattr(args, f"smart_socket_{idx}_device_key", ""),
                getattr(args, f"smart_socket_{idx}_product_key", ""),
                getattr(args, f"smart_socket_{idx}_name", ""),
            )
        for dev in SMART_SOCKET_FALLBACK_DEVICES:
            add_socket(
                dev.get("device_key", ""),
                dev.get("product_key", ""),
                dev.get("name", ""),
                dev.get("product_name", "Smart socket"),
            )
    return out


def _smart_socket_device_by_key(args, device_key: str):
    wanted = str(device_key or "").strip()
    for dev in _smart_socket_devices(args):
        if dev["device_key"] == wanted:
            return dev
    return None


def _smart_socket_bus_topics(socket_dev: dict) -> list:
    pk = socket_dev["product_key"]
    dk = socket_dev["device_key"]
    return [
        f"q/1/d/qd{pk}{dk}/bus",
        f"q/2/d/qd{pk}{dk}/bus",
        f"q/1/d/qd/{pk}/{dk}/bus",
        f"q/2/d/qd/{pk}/{dk}/bus",
    ]


def _smart_socket_frame(args, device_key: str, on: bool) -> bytes:
    raw = SMART_SOCKET_ON_HEX if on else SMART_SOCKET_OFF_HEX
    frame = bytearray(bytes.fromhex(raw.replace(" ", "")))
    seqs = getattr(args, "_smart_socket_seq", None)
    if not isinstance(seqs, dict):
        seqs = {}
    seq = int(seqs.get(device_key, int(time.time() * 1000) & 0xFF))
    seq = (seq + 1) & 0xFF
    seqs[device_key] = seq
    args._smart_socket_seq = seqs
    if len(frame) >= 7:
        frame[6] = seq
    return bytes(frame)


def _publish_smart_socket_cloud_command(socket_dev: dict, payload: bytes, discovered: dict) -> None:
    token = str(discovered.get("token") or "").strip()
    accel_url = _cloud_accel_url(discovered)
    accel_client = str(discovered.get("accel_client") or "").strip()
    if not token or not accel_url:
        raise RuntimeError("token o accel_url mancanti per comando smart socket")
    parsed = urllib.parse.urlparse(accel_url)
    if parsed.scheme not in ("ws", "wss"):
        raise RuntimeError(f"accel_url non valido: {accel_url}")

    try:
        import paho.mqtt.client as paho_mqtt
    except Exception as exc:
        raise RuntimeError("py3-paho-mqtt non installato") from exc

    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/ws/v2"
    prefix = accel_client if accel_client else "qu_landbook_"
    if not prefix.endswith("_"):
        prefix += "_"
    client_id = f"{prefix}{int(time.time() * 1000)}"

    cli = paho_mqtt.Client(client_id=client_id, transport="websockets", protocol=paho_mqtt.MQTTv311)
    cli.username_pw_set(username="", password=_normalize_auth_header(token))
    cli.ws_set_options(path=path)
    if parsed.scheme == "wss":
        cli.tls_set()
    cli.connect(host, port, keepalive=25)
    cli.loop_start()
    try:
        for topic in _smart_socket_bus_topics(socket_dev):
            info = cli.publish(topic, payload=payload, qos=1, retain=False)
            info.wait_for_publish(timeout=5)
            if info.rc != paho_mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"publish cloud fallito rc={info.rc} topic={topic}")
    finally:
        cli.loop_stop()
        cli.disconnect()


def _handle_smart_socket_command(topic, payload, mqtt, base_topic, args) -> bool:
    prefix = f"{base_topic}/smart_sockets/"
    suffix = "/set/switch"
    if not topic.startswith(prefix) or not topic.endswith(suffix):
        return False
    dk = topic[len(prefix):-len(suffix)]
    socket_dev = _smart_socket_device_by_key(args, dk)
    if not socket_dev:
        print(f"smart socket command ignored: unknown device {dk}", flush=True)
        return True
    state = payload.strip().upper()
    if state not in ("ON", "OFF"):
        return True
    if not _command_tx_allowed(args, f"smart_socket_{dk}", state, opposite_window=0.5):
        return True
    frame = _smart_socket_frame(args, dk, state == "ON")
    discovered = _load_discovered_cache()
    # Usa un token cloud fresco anche per il comando (altrimenti dopo la scadenza
    # lo switch smetterebbe di rispondere, come i sensori).
    cloud = _socket_cloud()
    if cloud is not None and cloud.available():
        try:
            fresh = cloud.ensure_token()
            if fresh:
                discovered["token"] = fresh
        except Exception as exc:
            print(f"smart socket token refresh failed {dk}: {exc}", flush=True)
    try:
        _publish_smart_socket_cloud_command(socket_dev, frame, discovered)
    except Exception as exc:
        print(f"smart socket command failed {dk}: {exc}", flush=True)
        return True
    mqtt.publish(f"{base_topic}/smart_sockets/{dk}/switch", state, retain=True)
    print(f"sent smart socket {dk} {state}", flush=True)
    return True


def _request_json(url: str, params: dict, token: str) -> dict:
    query = urllib.parse.urlencode(params)
    full_url = url + ("?" + query if query else "")
    req = urllib.request.Request(
        full_url,
        headers={
            "Accept": "application/json",
            "Authorization": _normalize_auth_header(token),
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _fetch_socket_attrs(discovered: dict, socket_dev: dict) -> dict:
    base_url = _cloud_base_url(discovered)
    token = str(discovered.get("token") or "").strip()
    if not base_url or not token:
        return {}
    j = _request_json(
        base_url + "/v2/binding/enduserapi/getDeviceBusinessAttributes",
        {"dk": socket_dev["device_key"], "pk": socket_dev["product_key"]},
        token,
    )
    if j.get("code") != 200:
        return {}
    data = j.get("data") or {}
    attrs = data.get("customizeTslInfo") or []
    out = {}
    for item in attrs:
        if not isinstance(item, dict):
            continue
        code = str(item.get("resourceCode") or "")
        value = item.get("resourceValce")
        if code == "switch":
            out["switch"] = "ON" if _boolish(value) else "OFF"
        elif code == "electricity_data":
            try:
                out["energy"] = round(float(value) / 1000.0, 3)
            except (TypeError, ValueError):
                pass
        elif code == "measure_data":
            try:
                measure = json.loads(value) if isinstance(value, str) else (value or {})
            except Exception:
                measure = {}
            try:
                voltage = round(float(measure.get("voltage_values") or 0) / 1000.0, 3)
                out["voltage"] = voltage
            except (TypeError, ValueError):
                voltage = None
                pass
            try:
                power = round(float(measure.get("power_value") or 0) / 1000.0, 3)
                out["power"] = power
            except (TypeError, ValueError):
                power = None
                pass
            try:
                current = round(float(measure.get("current_value") or 0) / 1000.0, 3)
                out["current"] = current
            except (TypeError, ValueError):
                current = None
                pass
            if voltage is not None and current is not None:
                apparent = round(float(voltage) * float(current), 3)
                out["apparent_power"] = apparent
                if apparent > 1 and power is not None:
                    out["power_factor"] = round(float(power) / apparent, 3)
                else:
                    out["power_factor"] = 0
    return out


def _fetch_socket_online_status(discovered: dict) -> dict | None:
    base_url = _cloud_base_url(discovered)
    token = str(discovered.get("token") or "").strip()
    if not base_url or not token:
        return None
    try:
        j = _request_json(
            base_url + "/v2/binding/enduserapi/userDeviceList",
            {"pageSize": 50, "isAssociated": 1},
            token,
        )
    except Exception as exc:
        _dprint(f"smart socket online status failed: {exc}", flush=True)
        return None
    if j.get("code") != 200:
        return None
    items = (j.get("data") or {}).get("list") or []
    out = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        dk = str(item.get("deviceKey") or item.get("device_key") or "").strip()
        if not dk:
            continue
        try:
            out[dk] = int(item.get("onlineStatus", 0) or 0) == 1
        except Exception:
            out[dk] = _boolish(item.get("onlineStatus"))
    return out


def _socket_liveness_topic(base_topic: str) -> str:
    """Topic di 'bridge vivo' DEDICATO alle prese, del tutto separato dalla
    availability della powerstation. Ha il proprio Last Will (vedi
    _start_socket_liveness): va offline solo quando il processo add-on si spegne,
    NON quando la powerstation ha problemi LAN/freeze."""
    return f"{base_topic}/smart_sockets/bridge_availability"


class _PahoPublisher:
    """Adatta un client paho all'interfaccia .publish(topic, payload, retain=False)
    usata dai publisher prese, così le funzioni esistenti restano invariate ma
    pubblicano sulla connessione DEDICATA alle prese invece che sul MqttClient
    della powerstation (evita anche di condividere lo stesso socket tra thread)."""

    def __init__(self, client):
        self._client = client

    def publish(self, topic, payload, retain=False):
        self._client.publish(topic, payload, qos=1, retain=retain)


class SmartSocketWorker:
    """Gestore prese COMPLETAMENTE indipendente dal loop LAN della powerstation.

    Possiede una propria connessione MQTT (con Last Will sul topic di liveness) e
    due attività autonome:
      • un thread di polling che ogni smart_socket_poll_interval secondi legge
        stato/lista dal cloud e pubblica su MQTT;
      • la sottoscrizione ai comandi HA .../smart_sockets/+/set/switch, gestiti
        nel callback on_message.

    Nessuna delle due dipende dallo stato LAN: se la powerstation va offline o in
    freeze, le prese continuano a leggersi e a rispondere ai comandi (e viceversa).
    """

    def __init__(self, args):
        self.args = args
        self.base_topic = args.topic
        self.liveness_topic = _socket_liveness_topic(args.topic)
        self._client = None
        self._pub = None
        self._poll_thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()  # serializza poll vs comando sullo stesso args

    def start(self):
        import paho.mqtt.client as paho_mqtt
        cli = paho_mqtt.Client(
            client_id=f"landbook_sock_worker_{int(time.time() * 1000)}",
            protocol=paho_mqtt.MQTTv311,
        )
        if getattr(self.args, "mqtt_user", ""):
            cli.username_pw_set(self.args.mqtt_user, getattr(self.args, "mqtt_password", "") or "")
        cli.will_set(self.liveness_topic, "offline", qos=1, retain=True)
        cli.on_connect = self._on_connect
        cli.on_message = self._on_message
        try:
            cli.reconnect_delay_set(min_delay=1, max_delay=30)
        except Exception:
            pass
        cli.connect(self.args.mqtt_host, int(self.args.mqtt_port), keepalive=30)
        cli.loop_start()
        self._client = cli
        self._pub = _PahoPublisher(cli)
        self._poll_thread = threading.Thread(
            target=self._poll_loop, name="smart-socket-poll", daemon=True
        )
        self._poll_thread.start()
        print(f"[socket-worker] prese attive (worker indipendente) su {self.liveness_topic}", flush=True)
        return self

    def _on_connect(self, client, userdata, flags, rc, *a):
        # Ripubblica 'online' e (ri)sottoscrive i comandi a ogni riconnessione.
        client.publish(self.liveness_topic, "online", qos=1, retain=True)
        client.subscribe(f"{self.base_topic}/smart_sockets/+/set/switch", qos=1)

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8", "replace")
        except Exception:
            return
        try:
            with self._lock:
                _handle_smart_socket_command(msg.topic, payload, self._pub, self.base_topic, self.args)
        except Exception as exc:
            print(f"[socket-worker] comando presa fallito: {exc}", flush=True)

    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                with self._lock:
                    _poll_smart_sockets(self._pub, self.base_topic, self.args)
            except Exception as exc:
                print(f"[socket-worker] poll prese fallito: {exc}", flush=True)
            interval = max(10, int(getattr(self.args, "smart_socket_poll_interval", 30) or 30))
            self._stop.wait(interval)

    def stop(self, graceful=True):
        """Ferma il worker. graceful=True fa DISCONNECT pulito lasciando il retained
        'online', così un self-restart del bridge NON manda le prese offline; il
        broker pubblica il Will 'offline' solo quando il processo muore davvero
        senza disconnessione pulita."""
        self._stop.set()
        cli = self._client
        self._client = None
        if cli is None:
            return
        if graceful:
            try:
                cli.publish(self.liveness_topic, "online", qos=1, retain=True)
            except Exception:
                pass
            try:
                cli.disconnect()   # DISCONNECT pulito → il broker NON pubblica il Will
            except Exception:
                pass
        try:
            cli.loop_stop()
        except Exception:
            pass


def _start_socket_liveness(args):
    """Avvia il worker prese indipendente e ritorna l'istanza (o None se le prese
    sono disabilitate o paho è assente). Sostituisce la vecchia connessione di sola
    liveness: ora la stessa connessione dedicata gestisce ANCHE poll e comandi delle
    prese, del tutto separati dal loop LAN della powerstation."""
    if not getattr(args, "smart_sockets_enabled", True):
        return None
    try:
        import paho.mqtt.client  # noqa: F401
    except Exception as exc:
        print(f"[socket-worker] prese non attive (paho assente): {exc}", flush=True)
        return None
    try:
        return SmartSocketWorker(args).start()
    except Exception as exc:
        print(f"[socket-worker] avvio fallito: {exc}", flush=True)
        return None


def _stop_socket_liveness(args) -> None:
    """Chiude in modo PULITO il worker prese (DISCONNECT esplicito, niente Will)
    mantenendo il retained 'online'. Da chiamare prima di un os.execv, così un
    self-restart del bridge (es. freeze powerstation) NON manda le prese offline."""
    worker = getattr(args, "_socket_liveness", None)
    if worker is None:
        return
    args._socket_liveness = None
    try:
        worker.stop(graceful=True)
    except Exception:
        pass



def _publish_smart_socket_discovery(mqtt, base_topic, args):
    parent_key = _device_key(args)
    socket_liveness_topic = _socket_liveness_topic(base_topic)
    if not getattr(args, "smart_sockets_enabled", True):
        mqtt.publish(f"homeassistant/sensor/{parent_key}/smart_socket_total_power/config", b"", retain=True)
        mqtt.publish(f"{base_topic}/smart_sockets/total_power", b"", retain=True)
        mqtt.publish(socket_liveness_topic, b"", retain=True)
        print("Smart socket discovery disabled: cleared total power entity", flush=True)
        return

    socket_devices = _smart_socket_devices(args)
    total_device = {
        "identifiers": [parent_key],
        "name": DEVICE_NAME,
        "manufacturer": "Landbook",
        "model": os.environ.get("PRODUCT_KEY") or "TSL LAN device",
        "serial_number": parent_key,
    }
    total_cfg = {
        "name": "Smart socket total power",
        "object_id": f"{DEVICE_OBJECT_ID}_smart_socket_total_power",
        "has_entity_name": True,
        "state_topic": f"{base_topic}/smart_sockets/total_power",
        "unit_of_measurement": "W",
        "device_class": "power",
        "state_class": "measurement",
        "force_update": True,
        "unique_id": f"{parent_key}_smart_socket_total_power",
        "device": total_device,
        "availability_topic": socket_liveness_topic,
        "payload_available": "online",
        "payload_not_available": "offline",
    }
    mqtt.publish(f"homeassistant/sensor/{parent_key}/smart_socket_total_power/config", json.dumps(total_cfg), retain=True)

    for dev in socket_devices:
        dk = dev["device_key"]
        socket_availability_topic = f"{base_topic}/smart_sockets/{dk}/availability"
        # Doppia disponibilità in modalità "all": la presa è disponibile solo se
        # SIA il bridge è vivo (topic di liveness DEDICATO alle prese, con Last
        # Will proprio → offline solo se l'add-on si spegne, indipendente dalla
        # powerstation) SIA la presa è online sul cloud. Così spegnendo il bridge
        # le prese vanno offline, ma un freeze/outage LAN della powerstation NON
        # le tocca, e resta il rilevamento della singola presa scollegata.
        socket_availability = [
            {"topic": socket_liveness_topic,
             "payload_available": "online", "payload_not_available": "offline"},
            {"topic": socket_availability_topic,
             "payload_available": "online", "payload_not_available": "offline"},
        ]
        slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in dk).strip("_")
        socket_name = str(dev.get("name") or dk)
        device = {
            "identifiers": [f"wonderfree_socket_{dk}"],
            "name": socket_name,
            "manufacturer": "Wonderfree",
            "model": dev.get("product_name") or dev.get("product_key") or "Smart socket",
            "serial_number": dk,
            "via_device": parent_key,
        }
        mqtt.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
        mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
        switch_cfg = {
            "name": "Switch",
            "object_id": f"wonderfree_socket_{slug}_device_switch",
            "has_entity_name": True,
            "state_topic": f"{base_topic}/smart_sockets/{dk}/switch",
            "command_topic": f"{base_topic}/smart_sockets/{dk}/set/switch",
            "payload_on": "ON",
            "payload_off": "OFF",
            "stat_t": f"{base_topic}/smart_sockets/{dk}/switch",
            "cmd_t": f"{base_topic}/smart_sockets/{dk}/set/switch",
            "pl_on": "ON",
            "pl_off": "OFF",
            "optimistic": False,
            "icon": "mdi:power-socket-eu",
            "unique_id": f"wonderfree_socket_{dk}_device_switch",
            "device": device,
            "availability": socket_availability,
            "availability_mode": "all",
        }
        mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", json.dumps(switch_cfg), retain=True)
        for sid, (name, unit, device_class, state_class) in SMART_SOCKET_SENSOR_DEFS.items():
            mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
            cfg = {
                "name": name,
                "object_id": f"wonderfree_socket_{slug}_device_{sid}",
                "has_entity_name": True,
                "state_topic": f"{base_topic}/smart_sockets/{dk}/{sid}",
                "unique_id": f"wonderfree_socket_{dk}_device_{sid}",
                "force_update": True,
                "device": device,
                "availability": socket_availability,
                "availability_mode": "all",
            }
            if unit:
                cfg["unit_of_measurement"] = unit
            if device_class:
                cfg["device_class"] = device_class
            if state_class:
                cfg["state_class"] = state_class
            mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", json.dumps(cfg), retain=True)
        mqtt.publish(socket_availability_topic, b"", retain=True)
    print(f"Smart socket discovery published: {len(socket_devices)}", flush=True)


def _remove_smart_socket_from_ha(mqtt, base_topic, dk) -> None:
    """Il device è stato eliminato dall'app: rimuovi le sue entità da HA
    pubblicando config vuote retained (HA le cancella da solo)."""
    mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", b"", retain=True)
    mqtt.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
    mqtt.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
    for sid in SMART_SOCKET_SENSOR_DEFS:
        mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", b"", retain=True)
        mqtt.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
    mqtt.publish(f"{base_topic}/smart_sockets/{dk}/availability", "offline", retain=True)


def _sync_smart_sockets_from_cloud(mqtt, base_topic, args, raw_devices) -> dict:
    """Allinea l'insieme delle prese alla device-list cloud (live).

    - Nuove prese → discovery HA + aggiunta in cache.
    - Prese assenti da >= SMART_SOCKET_NOT_FOUND_LIMIT poll → rimosse da HA e cache.
    Ritorna {device_key: online(bool)} dalla lista live.
    """
    from wf_socket_cloud import extract_sockets
    live = extract_sockets(raw_devices or [])
    live_by_dk = {d["device_key"]: d for d in live if d.get("device_key")}

    data = _load_discovered_cache()
    known = {
        d.get("device_key"): d
        for d in (data.get("smart_socket_devices") or [])
        if isinstance(d, dict) and d.get("device_key")
    }

    nf = getattr(args, "_socket_not_found", None)
    if not isinstance(nf, dict):
        nf = {}

    added = [dev for dk, dev in live_by_dk.items() if dk not in known]
    for dk in live_by_dk:
        nf.pop(dk, None)

    removed = []
    for dk in list(known):
        if dk not in live_by_dk:
            nf[dk] = nf.get(dk, 0) + 1
            print(f"[socket-cloud] {dk} assente dalla device-list "
                  f"({nf[dk]}/{SMART_SOCKET_NOT_FOUND_LIMIT})", flush=True)
            if nf[dk] >= SMART_SOCKET_NOT_FOUND_LIMIT:
                removed.append(dk)
    args._socket_not_found = nf

    if added or removed:
        new_set = []
        for dk, dev in live_by_dk.items():
            new_set.append({
                "device_key": dev.get("device_key", ""),
                "product_key": dev.get("product_key", ""),
                "name": dev.get("name", ""),
                "product_name": dev.get("product_name", "Smart socket"),
            })
        # Conserva le prese ancora nel periodo di grazia (assenti ma non oltre soglia).
        for dk, dev in known.items():
            if dk not in live_by_dk and dk not in removed:
                new_set.append(dev)
        data["smart_socket_devices"] = new_set
        _save_discovered_cache(data)

    if added:
        print(f"[socket-cloud] nuove prese rilevate: {[d['device_key'] for d in added]}", flush=True)
        _publish_smart_socket_discovery(mqtt, base_topic, args)
    for dk in removed:
        _remove_smart_socket_from_ha(mqtt, base_topic, dk)
        nf.pop(dk, None)
        print(f"[socket-cloud] presa {dk} eliminata dall'app — rimossa da HA", flush=True)

    return {dk: bool(dev.get("online")) for dk, dev in live_by_dk.items()}


def _poll_smart_sockets(mqtt, base_topic, args) -> None:
    if not getattr(args, "smart_sockets_enabled", True):
        return
    discovered = _load_discovered_cache()
    online_map = None
    used_cloud = False

    cloud = _socket_cloud()
    if cloud is not None and cloud.available():
        used_cloud = True
        try:
            token = cloud.ensure_token()
            if token:
                discovered["token"] = token
        except Exception as exc:
            _dprint(f"[socket-cloud] token refresh fallito: {exc}", flush=True)
        raw = cloud.list_devices()
        if raw is not None:
            # Device-list ok → auto-detect + rimozioni + mappa online live.
            online_map = _sync_smart_sockets_from_cloud(mqtt, base_topic, args, raw)
        # raw None = errore transitorio: online_map resta None → "assume online",
        # non tocchiamo le entità (come faceva il vecchio addon).

    if not used_cloud:
        # Nessuna credenziale / modulo assente: comportamento legacy.
        online_map = _fetch_socket_online_status(discovered)

    devices = _smart_socket_devices(args)
    if not devices:
        return
    total_power = 0.0
    any_power = False
    for dev in devices:
        dk = dev["device_key"]
        if online_map is not None:
            online = bool(online_map.get(dk, False))
            mqtt.publish(
                f"{base_topic}/smart_sockets/{dk}/availability",
                "online" if online else "offline",
                retain=True,
            )
            if not online:
                continue
        try:
            values = _fetch_socket_attrs(discovered, dev)
        except Exception as exc:
            _dprint(f"smart socket poll failed for {dev.get('device_key')}: {exc}", flush=True)
            continue
        if online_map is None and values:
            mqtt.publish(f"{base_topic}/smart_sockets/{dk}/availability", "online", retain=True)
        for key, value in values.items():
            mqtt.publish(f"{base_topic}/smart_sockets/{dk}/{key}", str(value), retain=True)
        if "power" in values:
            any_power = True
            total_power += float(values.get("power") or 0)
    if any_power:
        mqtt.publish(f"{base_topic}/smart_sockets/total_power", str(round(total_power, 3)), retain=True)
