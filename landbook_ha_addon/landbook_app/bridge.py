from __future__ import annotations

import signal

from .core import *
from .core import _num
from .smart_sockets import SmartSocketWorker

# Il vecchio set di discovery ("Test Powerstation") era un residuo dello sviluppo:
# duplicava ogni sensore del device buono ("Landbook LAN Device"). Le sue config
# sono state rimosse; qui resta solo la pulizia dei topic retained, che gira a
# ogni avvio perche' un broker ripristinato da backup puo' riproporle.
LEGACY_OBJECT_PREFIX = "test_powerstation_"
LEGACY_PURGE_WINDOW = 60.0

class MqttOut:
    def __init__(self, opts: dict[str, Any], dk: str, pk: str):
        self.opts = opts
        self.dk = dk or "unknown"
        self.pk = pk or "unknown"
        self.prefix = str(opt(opts, "topic_prefix", "landbook_test")).strip().strip("/") or "landbook_test"
        self.discovery_prefix = "homeassistant"
        self.base_topic = f"{self.prefix}/{self.dk}"
        self.compat_prefix = MAIN_TOPIC_PREFIX
        self.compat_base_topic = f"{self.compat_prefix}/{self.dk}"
        self.compat_availability_topic = f"{self.compat_base_topic}/availability"
        self.discovered: set[str] = set()
        self.compat_discovered: set[str] = set()
        self.controls: dict[str, dict[str, Any]] = {}
        self.control_codes: set[str] = set()
        self.pending_commands: list[tuple[str, str]] = []
        self.deferred_commands: list[tuple[float, str, str]] = []
        self.command_lock = threading.Lock()
        self.pending_control_states: dict[str, tuple[str, float]] = {}
        self.state_cache: dict[str, Any] = {}
        self.last_published: dict[str, str] = {}
        self.last_control_published: dict[str, str] = {}
        self.last_decoded_dump = ""
        self.last_wifi_frozen_alert = 0.0
        self.last_lan_online_at = 0.0
        self.client = mqtt.Client(client_id=f"landbook_{self.dk}_{random.randint(1000, 9999)}")
        self.client.will_set(self.compat_availability_topic, "offline", qos=1, retain=True)
        self.client.on_message = self.on_message
        user = str(opt(opts, "mqtt_user", "") or "")
        password = str(opt(opts, "mqtt_password", "") or "")
        if user:
            self.client.username_pw_set(user, password)
        host = str(opt(opts, "mqtt_host", "core-mosquitto"))
        port = int(opt(opts, "mqtt_port", 1883) or 1883)
        self.legacy_purge_until = time.time() + LEGACY_PURGE_WINDOW
        self.legacy_purge_done = False
        self.client.connect(host, port, keepalive=30)
        self.client.loop_start()
        self.client.subscribe(f"{self.discovery_prefix}/+/+/config", qos=0)
        self.publish_availability("online")
        self.publish_lan_connection("starting")
        self.publish_status("starting")
        self.cleanup_hidden_sensor_discovery()
        self.publish_startup_sensor_discovery()

    def purge_legacy_discovery(self, topic: str, msg) -> bool:
        if self.legacy_purge_done:
            return False
        if time.time() > self.legacy_purge_until:
            try:
                self.client.unsubscribe(f"{self.discovery_prefix}/+/+/config")
            except Exception:
                pass
            self.legacy_purge_done = True
            return False
        parts = topic.split("/")
        if len(parts) != 4 or parts[0] != self.discovery_prefix or parts[3] != "config":
            return False
        if not parts[2].startswith(LEGACY_OBJECT_PREFIX):
            return False
        if not (msg.payload or b""):
            return True
        self.client.publish(topic, b"", retain=True)
        log(f"rimosso discovery legacy topic={topic}")
        return True

    def on_message(self, _client, _userdata, msg) -> None:
        topic = str(msg.topic or "")
        if self.purge_legacy_discovery(topic, msg):
            return
        code = ""
        for prefix in (f"{self.base_topic}/set/", f"{self.compat_base_topic}/set/"):
            if topic.startswith(prefix):
                code = topic[len(prefix):]
                break
        if not code:
            return
        if getattr(msg, "retain", False):
            log(f"ignored retained command topic={topic}", "debug")
            return
        try:
            payload = msg.payload.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = ""
        with self.command_lock:
            self.deferred_commands = [item for item in self.deferred_commands if item[1] != code]
            self.pending_commands.append((code, payload))

    def drain_commands(self) -> list[tuple[str, str]]:
        now = time.time()
        with self.command_lock:
            items = list(self.pending_commands)
            self.pending_commands.clear()
            due = [item for item in self.deferred_commands if item[0] <= now]
            self.deferred_commands = [item for item in self.deferred_commands if item[0] > now]
        due.sort(key=lambda item: item[0])
        items.extend((code, payload) for _when, code, payload in due)
        return items

    def schedule_command(self, code: str, payload: str, delay: float = 2.0, replace: bool = True) -> None:
        when = time.time() + delay
        with self.command_lock:
            if replace:
                self.deferred_commands = [item for item in self.deferred_commands if item[1] != code]
            self.deferred_commands.append((when, code, str(payload)))

    def current_switch_state(self, code: str) -> str | None:
        pending = self.pending_control_states.get(code)
        if pending:
            state, until = pending
            if time.time() < until and state in ("ON", "OFF"):
                return state
        if code not in self.state_cache:
            return None
        return bool_state(self.state_cache.get(code))

    def publish_availability(self, value: str) -> None:
        self.client.publish(self.compat_availability_topic, value, retain=True)

    def publish_status(self, value: str) -> None:
        self.publish_sensor("status", value)

    def publish_lan_connection(self, value: str) -> None:
        self.publish_sensor("lan_connection", value)

    def compat_device_info(self) -> dict[str, Any]:
        return {
            "identifiers": [self.dk],
            "name": MAIN_DEVICE_NAME,
            "manufacturer": "Landbook",
            "model": self.pk or "TSL LAN device",
            "serial_number": self.dk,
        }

    def cleanup_hidden_sensor_discovery(self, extra_keys: set[str] | None = None) -> None:
        keys = set(HIDDEN_SENSOR_SLUGS)
        if extra_keys:
            keys.update(slugify(key) for key in extra_keys)
        for key in sorted(keys):
            self.client.publish(f"{self.discovery_prefix}/sensor/test_powerstation_{self.dk}_{key}/config", b"", retain=True)

    def publish_startup_sensor_discovery(self) -> None:
        for key in ("battery_remaining_wh", "remaining_time_minutes"):
            slug = slugify(key)
            self.discovery(slug, "")
            self.discovered.add(slug)
            compat_id = compat_sensor_id(slug)
            if compat_id:
                self.compat_sensor_discovery(compat_id, slug, "")
                self.compat_discovered.add(compat_id)

    def publish_sensor(self, key: str, value: Any) -> None:
        key = slugify(key)
        if key not in self.discovered:
            self.discovery(key, value)
            self.discovered.add(key)
        compat_id = compat_sensor_id(key)
        if not compat_id:
            return
        state = format_sensor_state(key, value)
        # publish_decoded ripassa l'intera cache a ogni frame, quindi la maggior
        # parte di questi valori e' identica a quella di un attimo prima. Il
        # topic e' retained: HA ha gia' il valore buono e lo ritrova anche dopo
        # un riavvio, ripeterlo serve solo a caricare il broker.
        if self.last_published.get(key) == state:
            return
        self.last_published[key] = state
        if compat_id not in self.compat_discovered:
            self.compat_sensor_discovery(compat_id, key, value)
            self.compat_discovered.add(compat_id)
        self.client.publish(f"{self.compat_base_topic}/sensors/{compat_id}", state, retain=True)

    def discovery(self, key: str, sample: Any) -> None:
        """Cancella la vecchia config retained "Test Powerstation" per questa
        chiave. Il set di discovery vero e' compat_sensor_discovery."""
        self.client.publish(
            f"{self.discovery_prefix}/sensor/test_powerstation_{self.dk}_{key}/config",
            b"", retain=True,
        )

    def compat_sensor_discovery(self, compat_id: str, source_key: str, sample: Any) -> None:
        payload: dict[str, Any] = {
            "name": human_name_for_sensor(compat_id),
            "object_id": f"{MAIN_DEVICE_OBJECT_ID}_{compat_id}",
            "has_entity_name": True,
            "unique_id": f"{self.dk}_{compat_id}",
            "state_topic": f"{self.compat_base_topic}/sensors/{compat_id}",
            "availability_topic": self.compat_availability_topic,
            "force_update": True,
            "device": self.compat_device_info(),
        }
        unit = unit_for(compat_id)
        if unit:
            payload["unit_of_measurement"] = unit
        dc = device_class_for(compat_id)
        if dc:
            payload["device_class"] = dc
        precision = display_precision_for(compat_id)
        if precision is not None:
            payload["suggested_display_precision"] = precision
        if has_measurement_state_class(compat_id, sample):
            payload["state_class"] = "measurement"
        category = entity_category_for(compat_id)
        if category:
            payload["entity_category"] = category
        topic = f"{self.discovery_prefix}/sensor/{self.dk}/{compat_id}/config"
        self.client.publish(topic, b"", retain=True)
        self.client.publish(topic, json.dumps(payload), retain=True)

    def compat_control_object_id(self, code: str, kind: str) -> str:
        if kind == "switch":
            return COMPAT_SWITCH_OBJECT_IDS.get(code, f"{MAIN_DEVICE_OBJECT_ID}_{code}")
        if kind == "select":
            return COMPAT_SELECT_OBJECT_IDS.get(code, f"{MAIN_DEVICE_OBJECT_ID}_{code}")
        if kind == "number":
            return COMPAT_NUMBER_OBJECT_IDS.get(code, f"{MAIN_DEVICE_OBJECT_ID}_{code}")
        return f"{MAIN_DEVICE_OBJECT_ID}_{code}"

    def compat_control_discovery(self, code: str, info: dict[str, Any]) -> None:
        kind = str(info.get("kind") or "")
        object_id = self.compat_control_object_id(code, kind)
        common = {
            "name": info.get("name") or code,
            "object_id": object_id,
            "has_entity_name": True,
            "unique_id": f"{self.dk}_{code}",
            "command_topic": f"{self.compat_base_topic}/set/{code}",
            "state_topic": f"{self.compat_base_topic}/cmd_state/{code}",
            "availability_topic": self.compat_availability_topic,
            "optimistic": False,
            "device": self.compat_device_info(),
        }
        if kind == "switch":
            payload = dict(common)
            payload.update({"payload_on": "ON", "payload_off": "OFF", "state_on": "ON", "state_off": "OFF"})
            domain = "switch"
        elif kind == "select":
            options = info.get("options") or {}
            if not options:
                return
            payload = dict(common)
            payload["options"] = [options[k] for k in sorted(options)]
            domain = "select"
        elif kind == "number":
            payload = dict(common)
            payload["mode"] = "slider"
            if info.get("min") is not None:
                payload["min"] = info.get("min")
            if info.get("max") is not None:
                payload["max"] = info.get("max")
            if info.get("step") is not None:
                payload["step"] = info.get("step")
            unit = info.get("unit") or unit_for(code)
            if unit:
                payload["unit_of_measurement"] = unit
            domain = "number"
        else:
            return
        topic = f"{self.discovery_prefix}/{domain}/{self.dk}/{code}/config"
        self.client.publish(topic, json.dumps(payload), retain=True)

    def publish_control_discovery(self, controls: dict[str, dict[str, Any]]) -> None:
        self.controls = controls
        self.control_codes = set(controls)
        self.cleanup_hidden_sensor_discovery(self.control_codes)
        for code in ENUM_AS_SWITCH:
            slug = slugify(code)
            self.client.publish(f"{self.discovery_prefix}/select/test_powerstation_{self.dk}_{slug}/config", b"", retain=True)
            self.client.publish(f"{self.discovery_prefix}/select/{self.dk}/{code}/config", b"", retain=True)
        for code in HIDDEN_CONTROL_CODES:
            slug = slugify(code)
            for domain in ("switch", "select", "number"):
                self.client.publish(f"{self.discovery_prefix}/{domain}/test_powerstation_{self.dk}_{slug}/config", b"", retain=True)
                self.client.publish(f"{self.discovery_prefix}/{domain}/{self.dk}/{code}/config", b"", retain=True)
        for code, info in sorted(controls.items()):
            slug = slugify(code)
            for domain in ("switch", "select", "number"):
                self.client.publish(f"{self.discovery_prefix}/{domain}/test_powerstation_{self.dk}_{slug}/config", b"", retain=True)
            self.compat_control_discovery(code, info)
        self.client.subscribe(f"{self.base_topic}/set/+", qos=1)
        self.client.subscribe(f"{self.compat_base_topic}/set/+", qos=1)
        counts = {
            "switch": sum(1 for x in controls.values() if x.get("kind") == "switch"),
            "select": sum(1 for x in controls.values() if x.get("kind") == "select"),
            "number": sum(1 for x in controls.values() if x.get("kind") == "number"),
        }
        log(f"published controls switches={counts['switch']} selects={counts['select']} numbers={counts['number']}")

    def publish_control_state(self, code: str, value: Any) -> None:
        info = self.controls.get(code)
        if not info:
            return
        kind = info.get("kind")
        state = None
        if kind == "switch":
            if code in ENUM_AS_SWITCH:
                text = str(value).strip().upper()
                if text in ("ON", "OFF"):
                    state = text
                else:
                    number = _num(value)
                    state = "ON" if number is not None and int(number) == int(ENUM_AS_SWITCH[code]) else "OFF"
            else:
                state = bool_state(value)
        elif kind == "select":
            options = info.get("options") or {}
            if str(value) in set(str(x) for x in options.values()):
                state = str(value)
            else:
                try:
                    state = options.get(int(float(value)), str(value))
                except Exception:
                    state = str(value)
        elif kind == "number":
            if code == "output_power_set":
                n = _num(value)
                if n is not None and n > 800 and n % 10 == 0:
                    value = n / 10.0
            state = format_state(value)
        if state is not None:
            pending = self.pending_control_states.get(code)
            if pending:
                pending_state, until = pending
                if time.time() < until:
                    state = pending_state
                else:
                    self.pending_control_states.pop(code, None)
            # Stesso discorso dei sensori: lo stato dei controlli viene ripassato
            # a ogni frame ed e' quasi sempre identico. Il topic e' retained.
            if self.last_control_published.get(code) == state:
                return
            self.last_control_published[code] = state
            self.client.publish(f"{self.compat_base_topic}/cmd_state/{code}", state, retain=True)

    def mark_pending_control_state(self, code: str, state: Any, seconds: float = 12.0) -> None:
        # Qui si pubblica sempre: e' la conferma ottimistica di un comando appena
        # dato, deve arrivare in dashboard anche se coincide con lo stato noto.
        text = format_state(state)
        self.pending_control_states[code] = (text, time.time() + seconds)
        self.last_control_published[code] = text
        self.client.publish(f"{self.compat_base_topic}/cmd_state/{code}", text, retain=True)

    def publish_wifi_frozen_alert(self, *, reason: str, streak: int = 1, duration: float | None = None) -> bool:
        if not bool_opt(self.opts, "freeze_detection_enabled", True):
            return False
        now = time.time()
        cooldown = float(opt(self.opts, "freeze_alert_cooldown", FREEZE_ALERT_COOLDOWN) or FREEZE_ALERT_COOLDOWN)
        if self.last_wifi_frozen_alert and now - self.last_wifi_frozen_alert < cooldown:
            return False
        messages = {
            "sensor_silence": "PowerStation WiFi/LAN reporting frozen. Riavviare il WiFi del router o la powerstation.",
            "rich_telemetry_stale": "PowerStation WiFi/LAN reporting frozen. Riavviare il WiFi del router o la powerstation.",
            "lan_unreachable": "PowerStation LAN unreachable. Riavviare il WiFi del router o la powerstation.",
        }
        payload: dict[str, Any] = {
            "reason": reason,
            "ts": int(now),
            "message": messages.get(reason, messages["sensor_silence"]),
            "streak": int(streak),
        }
        if duration is not None:
            payload["duration"] = int(duration)
        self.client.publish(f"{self.compat_base_topic}/event/wifi_frozen", json.dumps(payload), retain=False)
        self.last_wifi_frozen_alert = now
        log(f"wifi_frozen published reason={reason} duration={payload.get('duration', 0)}s")
        return True

    def publish_control_states(self, decoded: dict[str, Any]) -> None:
        for code in self.control_codes:
            if code in decoded:
                self.publish_control_state(code, decoded[code])

    def publish_decoded(self, decoded: dict[str, Any]) -> None:
        decoded = prune_decoded_for_cache(decoded)
        self.state_cache.update(decoded)
        apply_aliases(self.state_cache)
        update_battery_remaining_wh(self.state_cache, self.opts)
        device_status = derive_device_status(self.state_cache)
        if device_status:
            self.state_cache["device_status"] = device_status
        self.publish_control_states(self.state_cache)
        for key, value in sorted(self.state_cache.items()):
            if isinstance(value, (dict, list)):
                continue
            if not should_publish_sensor_key(key, self.control_codes):
                continue
            self.publish_sensor(key, value)
        visible = {
            key: value for key, value in sorted(self.state_cache.items())
            if not isinstance(value, (dict, list)) and should_publish_sensor_key(key, self.control_codes)
        }
        # E' il messaggio piu' pesante del giro (tutta la cache in un JSON) ed e'
        # solo diagnostico: si ripubblica quando cambia qualcosa, non a ogni frame.
        dump = json.dumps(visible, ensure_ascii=False)
        if dump != self.last_decoded_dump:
            self.last_decoded_dump = dump
            self.client.publish(f"{self.base_topic}/last_decoded_json", dump, retain=False)

    def stop(self) -> None:
        try:
            self.publish_lan_connection("offline")
            self.publish_status("stopped")
            self.publish_availability("offline")
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass


def send_encrypted(sock: socket.socket, cmd: int, pid: int, plain: bytes, key: bytes, iv: bytes) -> None:
    sock.sendall(encode_cmd(cmd, pid, aes_encrypt(plain, key, iv)))


def encode_control_payload(info: dict[str, Any], payload: str) -> tuple[bytes, Any]:
    tag_id = int(info["id"])
    code = str(info.get("code") or "")
    kind = str(info.get("kind") or "")
    typ = str(info.get("type") or "").upper()
    if kind == "switch":
        state = str(payload).strip().upper()
        if state not in ("ON", "OFF"):
            raise ValueError("switch payload must be ON or OFF")
        value = state == "ON"
        if code in ENUM_AS_SWITCH:
            return ttlv_number(tag_id, int(ENUM_AS_SWITCH[code]) if value else 0), state
        if typ == "BOOL":
            return ttlv_bool(tag_id, value), state
        return ttlv_number(tag_id, 1 if value else 0), state
    if kind == "select":
        options = info.get("options") or {}
        label_to_value = {str(label): int(value) for value, label in options.items()}
        if payload in label_to_value:
            value = label_to_value[payload]
        else:
            value = int(float(payload))
            if value not in options:
                raise ValueError(f"select value {value} is not in TSL options")
        return ttlv_number(tag_id, value), options.get(value, str(value))
    if kind == "number":
        value = float(payload)
        lo = info.get("min")
        hi = info.get("max")
        step = float(info.get("step") or 1)
        if lo is not None:
            value = max(float(lo), value)
        if hi is not None:
            value = min(float(hi), value)
        if step > 0:
            value = round(value / step) * step
        value = int(value) if float(value).is_integer() else value
        return ttlv_number(tag_id, int(round(float(value)))), value
    raise ValueError(f"unsupported control kind {kind}")


def handle_mqtt_commands(sock: socket.socket, mqtt_out: MqttOut, controls: dict[str, dict[str, Any]],
                         pid: int, key: bytes, iv: bytes) -> int:
    for code, payload in mqtt_out.drain_commands():
        info = controls.get(code)
        if not info:
            log(f"ignored unknown command {code}", "warning")
            continue
        try:
            preserve_grid_state = None
            if code == "mode" and "grid_power_switch_set" in controls:
                preserve_grid_state = mqtt_out.current_switch_state("grid_power_switch_set")
            plain, state = encode_control_payload(info, payload)
            send_encrypted(sock, CMD_WRITE, pid, plain, key, iv)
            mqtt_out.mark_pending_control_state(code, state)
            log(f"sent control {code}={state} pid={pid}")
            pid += 1
            if preserve_grid_state in ("ON", "OFF"):
                mqtt_out.mark_pending_control_state("grid_power_switch_set", preserve_grid_state, seconds=24.0)
                for delay in (2.0, 8.0, 16.0):
                    mqtt_out.schedule_command("grid_power_switch_set", preserve_grid_state, delay=delay, replace=False)
                log(f"scheduled grid_power_switch_set preserve={preserve_grid_state} after mode change", "debug")
        except Exception as exc:
            log(f"command {code} failed: {exc}", "warning")
    return pid


def run_lan_session(opts: dict[str, Any], mqtt_out: MqttOut, host: str, port: int, key_hex: str,
                    schema: dict[int, dict[str, Any]], read_ids: list[int],
                    controls: dict[str, dict[str, Any]]) -> None:
    sock, key, iv, status = connect_and_login(host, port, key_hex)
    sock.settimeout(0.7)
    log(f"LAN login OK host={host}:{port} status={status}")
    mqtt_out.last_lan_online_at = time.time()
    mqtt_out.publish_availability("online")
    mqtt_out.publish_lan_connection("lan_connected")
    mqtt_out.publish_status("lan_connected")
    pid = 2
    hfr_id = 19
    for ident, info in schema.items():
        if str(info.get("code")) == "high_frequency_reporting":
            hfr_id = int(ident)
            break
    hfr_mode = int(opt(opts, "hfr_mode", 1) or 1)
    if hfr_mode not in (0, 1, 2, 3):
        log(f"invalid hfr_mode={hfr_mode}; using LAN HFR (1)", "warning")
        hfr_mode = 1
    read_payload = b"".join(int(x).to_bytes(2, "big") for x in read_ids)
    report_interval = max(5, int(opt(opts, "read_interval", 10) or 10))
    rearm_interval = max(10, int(opt(opts, "rearm_interval", 20) or 20))
    frame_timeout = max(15, int(opt(opts, "frame_timeout", 30) or 30))
    freeze_enabled = bool_opt(opts, "freeze_detection_enabled", True)
    freeze_after = max(30.0, float(opt(opts, "freeze_alert_after", FREEZE_ALERT_AFTER) or FREEZE_ALERT_AFTER))
    telemetry_timeout = max(frame_timeout, report_interval * 3, int(freeze_after) + 30)

    send_encrypted(sock, CMD_HEARTBEAT, pid, ttlv_number(1, report_interval) + ttlv_number(2, 1), key, iv)
    log(f"sent p9 heartbeat interval={report_interval}s pid={pid}")
    pid += 1
    time.sleep(0.2)
    send_encrypted(sock, CMD_WRITE, pid, ttlv_number(hfr_id, hfr_mode), key, iv)
    log(f"sent cmd19 high_frequency_reporting id={hfr_id} value={hfr_mode} pid={pid}")
    pid += 1
    time.sleep(0.2)
    send_encrypted(sock, CMD_READ, pid, read_payload, key, iv)
    log(f"sent cmd17 read-all ids={len(read_ids)} pid={pid}")
    pid += 1

    buf = b""
    last_ping = time.time()
    last_read = time.time()
    last_rearm = time.time()
    last_frame = time.time()
    last_telemetry = time.time()
    while True:
        now = time.time()
        pid = handle_mqtt_commands(sock, mqtt_out, controls, pid, key, iv)
        if now - last_frame > frame_timeout:
            raise RuntimeError(f"no LAN frames for {frame_timeout}s")
        telemetry_stale_for = now - last_telemetry
        if freeze_enabled and telemetry_stale_for >= freeze_after and now - last_frame < frame_timeout:
            if mqtt_out.publish_wifi_frozen_alert(reason="sensor_silence", duration=telemetry_stale_for):
                mqtt_out.publish_lan_connection("frozen")
                mqtt_out.publish_status("frozen")
            raise RuntimeError(f"sensor telemetry stale for {int(telemetry_stale_for)}s")
        if now - last_telemetry > telemetry_timeout:
            raise RuntimeError(f"no useful telemetry frames for {telemetry_timeout}s")
        if now - last_ping >= 10:
            sock.sendall(encode_cmd(CMD_PING, pid))
            log(f"sent p7 ping pid={pid}", "debug")
            pid += 1
            last_ping = now
        if now - last_rearm >= rearm_interval:
            send_encrypted(sock, CMD_HEARTBEAT, pid, ttlv_number(1, report_interval) + ttlv_number(2, 1), key, iv)
            log(f"sent p9 re-heartbeat pid={pid}", "debug")
            pid += 1
            time.sleep(0.15)
            send_encrypted(sock, CMD_WRITE, pid, ttlv_number(hfr_id, hfr_mode), key, iv)
            log(f"sent cmd19 re-arm id={hfr_id} value={hfr_mode} pid={pid}", "debug")
            pid += 1
            last_rearm = now
        if now - last_read >= report_interval:
            send_encrypted(sock, CMD_READ, pid, read_payload, key, iv)
            log(f"sent cmd17 read-all ids={len(read_ids)} pid={pid}", "debug")
            pid += 1
            last_read = now
        try:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("LAN socket closed")
            buf += chunk
            last_frame = time.time()
        except socket.timeout:
            continue
        frames, buf = extract_frames(buf)
        for frame in frames:
            cmd = int(frame.get("cmd"))
            payload = frame.get("payload", b"")
            if cmd == CMD_PING:
                # The station pings us as well, and tears the session down when
                # the pong does not come back.
                sock.sendall(encode_cmd(CMD_PONG, pid))
                pid += 1
                log("replied p8 pong to station ping", "debug")
                continue
            if cmd == CMD_HEARTBEAT and not payload:
                # A bare p9 from the station is its own heartbeat, not an answer
                # to the encrypted one we send: it wants the frame echoed back.
                sock.sendall(encode_cmd(CMD_HEARTBEAT, pid))
                pid += 1
                log("echoed p9 heartbeat back to station", "debug")
                continue
            if cmd == CMD_PONG:
                log("received p8 pong", "debug")
                continue
            if payload and len(payload) % 16 == 0:
                plain = aes_decrypt(payload, key, iv)
                if cmd in (CMD_REPORT, CMD_WRITE_ACK):
                    try:
                        decoded = decode_payload(plain, schema)
                    except Exception as exc:
                        log(f"decode failed cmd={cmd}: {exc}", "warning")
                        continue
                    if decoded:
                        log(f"decoded cmd={cmd} keys={len(decoded)} sample={short_sample(decoded)}")
                        pruned = prune_decoded_for_cache(decoded)
                        if any(should_publish_sensor_key(key, set(controls)) for key in pruned):
                            last_telemetry = time.time()
                        mqtt_out.publish_decoded(decoded)
                    elif cmd == CMD_WRITE_ACK:
                        log("write ack", "debug")
                else:
                    log(f"encrypted cmd={cmd} plain_len={len(plain)}", "debug")
            else:
                log(f"frame cmd={cmd} payload_len={len(payload)}", "debug")


def short_sample(decoded: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "battery_percentage", "battery_voltage", "battery_current", "battery_total_power",
        "remaining_time_minutes",
        "pv_input_power", "total_input_power", "total_output_power", "ac_output_power",
        "grid_b_power", "device_status", "fault_code", "high_frequency_reporting",
    ]
    return {key: decoded[key] for key in keys if key in decoded}


def is_lan_unreachable_error(message: str) -> bool:
    text = str(message or "").lower()
    if "udp discovery failed: set device_host" in text:
        return False
    return any(token in text for token in (
        "host is unreachable",
        "network is unreachable",
        "no route to host",
        "connection timed out",
        "timed out",
        "timeout",
        "connection refused",
        "no nonce from device",
        "udp discovery failed",
    ))


def main() -> None:
    migrate_legacy_state()
    opts = read_options()
    os.environ["LOG_LEVEL"] = str(opt(opts, "log_level", "info")).lower()
    timezone = str(opt(opts, "timezone", "Europe/Rome") or "Europe/Rome")
    os.environ["TZ"] = timezone
    try:
        time.tzset()
    except Exception:
        pass

    key_hex = ""
    dk = str(opt(opts, "device_key", "") or "").strip()
    pk = ""
    mqtt_out: MqttOut | None = None
    socket_worker: SmartSocketWorker | None = None
    cached_host, cached_port = load_host_cache()
    configured_host = str(opt(opts, "device_host", "") or "").strip()
    scan_cidr = str(opt(opts, "udp_scan_cidr", "") or "").strip()
    if cached_host and not configured_host and scan_cidr and not host_matches_any_cidr(cached_host, (scan_cidr, cidr_from_host(local_ipv4_guess()))):
        log(f"ignoring cached LAN host {cached_host}; outside udp_scan_cidr={normalized_cidr(scan_cidr) or scan_cidr}", "warning")
        cached_host = ""
    last_host = configured_host or cached_host
    last_port = int(opt(opts, "device_port", cached_port or DEFAULT_CONTROL_PORT) or DEFAULT_CONTROL_PORT)
    lan_unreachable_since: float | None = None
    lan_unreachable_freeze_after = max(15.0, float(opt(opts, "frame_timeout", 30) or 30))
    sensor_freeze_attempts: list[float] = []
    sensor_freeze_attempt_window = 90.0
    sensor_freeze_attempt_limit = 2

    def _graceful_shutdown(_signum, _frame) -> None:
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _graceful_shutdown)
        signal.signal(signal.SIGINT, _graceful_shutdown)
    except Exception:
        pass

    try:
        key_hex, dk, pk = fetch_lan_key_from_cloud(opts)
        schema, read_ids = load_tsl_schema()
        controls = build_control_catalogs()
        log(f"TSL/read list loaded: ids={len(read_ids)} {read_ids}")
        log(f"TSL controls loaded: {sorted(controls)}")
        # Il dispositivo padre ("Landbook LAN Device") nasce dalla discovery
        # di MqttOut, pubblicata appena il client MQTT si connette (non serve
        # la LAN). Va creato PRIMA del worker prese: altrimenti le prese, che
        # arrivano dal cloud, escono prima del padre e HA fissa via_device solo
        # alla creazione, lasciando le prese slegate (es. quando la stazione e'
        # irraggiungibile per un cambio rete). Il breve respiro lascia a HA il
        # tempo di registrare il padre prima delle prese.
        if mqtt_out is None:
            mqtt_out = MqttOut(opts, dk, pk)
            mqtt_out.publish_control_discovery(controls)
        if bool_opt(opts, "smart_sockets_enabled", True):
            time.sleep(2.0)
            socket_worker = SmartSocketWorker(opts, dk, pk).start()
        while True:
            try:
                try:
                    host, port, discovered_dk, discovered_pk = udp_discover(opts, dk)
                    last_host, last_port = host, int(port)
                    save_host_cache(last_host, last_port)
                except RuntimeError as exc:
                    if "UDP discovery failed" not in str(exc) or not last_host:
                        raise
                    host, port, discovered_dk, discovered_pk = last_host, last_port, dk, pk
                    log(f"UDP discovery failed, trying last known LAN host {host}:{port}", "warning")
                dk = discovered_dk or dk
                pk = discovered_pk or pk
                if mqtt_out is None:
                    mqtt_out = MqttOut(opts, dk, pk)
                    mqtt_out.publish_control_discovery(controls)
                mqtt_out.publish_lan_connection("connecting_lan")
                mqtt_out.publish_status("connecting_lan")
                run_lan_session(opts, mqtt_out, host, int(port), key_hex, schema, read_ids, controls)
            except Exception as exc:
                msg = str(exc)
                log(f"session error: {msg}", "warning")
                now = time.time()
                retry_delay = 5.0
                sensor_stale = "sensor telemetry stale" in msg or "no useful telemetry frames" in msg
                if sensor_stale:
                    sensor_freeze_attempts = [
                        when for when in sensor_freeze_attempts
                        if now - when <= sensor_freeze_attempt_window
                    ]
                    sensor_freeze_attempts.append(now)
                    log(
                        f"sensor freeze reconnect attempt "
                        f"{len(sensor_freeze_attempts)}/{sensor_freeze_attempt_limit} "
                        f"in {int(sensor_freeze_attempt_window)}s window",
                        "warning",
                    )
                lan_unreachable = is_lan_unreachable_error(msg)
                if lan_unreachable:
                    if (
                        mqtt_out
                        and lan_unreachable_since is not None
                        and mqtt_out.last_lan_online_at > lan_unreachable_since
                    ):
                        lan_unreachable_since = None
                    if lan_unreachable_since is None:
                        lan_unreachable_since = now
                    duration = now - lan_unreachable_since
                else:
                    lan_unreachable_since = None
                    duration = 0.0
                if mqtt_out:
                    if lan_unreachable and duration >= lan_unreachable_freeze_after:
                        mqtt_out.publish_lan_connection("offline")
                        mqtt_out.publish_status("offline")
                        mqtt_out.publish_availability("offline")
                    elif sensor_stale and len(sensor_freeze_attempts) >= sensor_freeze_attempt_limit:
                        mqtt_out.publish_lan_connection("frozen")
                        mqtt_out.publish_status("frozen")
                        mqtt_out.publish_availability("online")
                        retry_delay = 60.0
                        sensor_freeze_attempts.clear()
                        log(
                            "Powerstation LAN frozen after repeated sensor silence; "
                            "keeping smart sockets alive and retrying LAN in 60s",
                            "warning",
                        )
                    else:
                        mqtt_out.publish_lan_connection("reconnecting")
                        mqtt_out.publish_status("reconnecting")
                        log(
                            f"keeping availability online during transient reconnect "
                            f"lan_unreachable={lan_unreachable} duration={duration:.1f}s",
                            "debug",
                        )
                if "login rejected" in msg:
                    log("LAN key rejected, refreshing from cloud")
                    key_hex, dk, pk = fetch_lan_key_from_cloud(opts)
                time.sleep(retry_delay)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(f"fatal: {exc}", "error")
        traceback.print_exc()
        if mqtt_out:
            mqtt_out.publish_lan_connection("fatal")
            mqtt_out.publish_status("fatal")
        time.sleep(3)
        raise
    finally:
        if socket_worker:
            socket_worker.stop()
        if mqtt_out:
            mqtt_out.stop()


if __name__ == "__main__":
    main()
