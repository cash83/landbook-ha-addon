from __future__ import annotations

from .core import *
from .core import _num

class SmartSocketWorker:
    def __init__(self, opts: dict[str, Any], parent_dk: str, parent_pk: str):
        self.opts = opts
        self.parent_dk = parent_dk
        self.parent_pk = parent_pk or "unknown"
        self.base_topic = f"{MAIN_TOPIC_PREFIX}/{parent_dk}"
        self.liveness_topic = socket_liveness_topic(self.base_topic)
        self.cloud = SmartSocketCloud(opts)
        self.devices: dict[str, dict[str, Any]] = {}
        self.not_found: dict[str, int] = {}
        self.seq_by_dk: dict[str, int] = {}
        self.command_recent: dict[tuple[str, str], float] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.client: mqtt.Client | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> "SmartSocketWorker | None":
        if not bool_opt(self.opts, "smart_sockets_enabled", True):
            log("smart sockets disabled")
            return None
        client_id = f"landbook_sockets_{self.parent_dk}_{random.randint(1000, 9999)}"
        client = mqtt.Client(client_id=client_id)
        user = str(opt(self.opts, "mqtt_user", "") or "")
        password = str(opt(self.opts, "mqtt_password", "") or "")
        if user:
            client.username_pw_set(user, password)
        client.will_set(self.liveness_topic, "offline", qos=1, retain=True)
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(str(opt(self.opts, "mqtt_host", "core-mosquitto")), int(opt(self.opts, "mqtt_port", 1883) or 1883), keepalive=30)
        client.loop_start()
        self.client = client
        self.publish_liveness("online")
        self.refresh_devices(publish=True)
        self.publish_discovery()
        self.thread = threading.Thread(target=self.poll_loop, name="test-smart-sockets", daemon=True)
        self.thread.start()
        log(f"smart socket worker started on {self.liveness_topic}")
        return self

    def publish_liveness(self, state: str) -> None:
        if self.client is not None:
            self.client.publish(self.liveness_topic, state, qos=1, retain=True)

    def publish(self, topic: str, payload: Any, retain: bool = False) -> None:
        if self.client is not None:
            self.client.publish(topic, payload, qos=1, retain=retain)

    def on_connect(self, client, userdata, flags, rc, *args) -> None:
        client.publish(self.liveness_topic, "online", qos=1, retain=True)
        client.subscribe(f"{self.base_topic}/smart_sockets/+/set/switch", qos=1)

    def on_message(self, client, userdata, msg) -> None:
        if getattr(msg, "retain", False):
            log(f"ignored retained smart socket command topic={msg.topic}", "debug")
            return
        try:
            payload = msg.payload.decode("utf-8", "replace")
        except Exception:
            return
        with self.lock:
            self.handle_command(str(msg.topic), payload)

    def manual_devices(self) -> list[dict[str, Any]]:
        return manual_smart_socket_devices(self.opts)

    def refresh_devices(self, publish: bool = False) -> list[dict[str, Any]]:
        raw = self.cloud.list_devices()
        changed = False
        if raw is None:
            return list(self.devices.values()) or self.manual_devices()
        live = extract_smart_socket_devices(raw)
        if not live and not self.devices:
            live = self.manual_devices()
        live_by_dk = {dev["device_key"]: dev for dev in live}

        for dk, dev in live_by_dk.items():
            self.not_found.pop(dk, None)
            if dk not in self.devices or self.devices[dk] != dev:
                self.devices[dk] = dev
                changed = True

        for dk in list(self.devices):
            if dk in live_by_dk:
                continue
            self.not_found[dk] = self.not_found.get(dk, 0) + 1
            log(f"smart socket {mask(dk)} missing from cloud list ({self.not_found[dk]}/{SMART_SOCKET_NOT_FOUND_LIMIT})", "debug")
            if self.not_found[dk] >= SMART_SOCKET_NOT_FOUND_LIMIT:
                self.remove_socket_from_ha(dk)
                self.devices.pop(dk, None)
                self.not_found.pop(dk, None)
                changed = True

        if publish and changed:
            self.publish_discovery()
        return list(self.devices.values())

    def device_info(self, dev: dict[str, Any]) -> dict[str, Any]:
        dk = str(dev.get("device_key") or "")
        return {
            "identifiers": [f"wonderfree_socket_{dk}"],
            "name": str(dev.get("name") or dk),
            "manufacturer": "Wonderfree",
            "model": str(dev.get("product_name") or dev.get("product_key") or "Smart socket"),
            "serial_number": dk,
            "via_device": self.parent_dk,
        }

    def publish_discovery(self) -> None:
        if self.client is None:
            return
        self.publish_liveness("online")
        parent_device = {
            "identifiers": [self.parent_dk],
            "name": MAIN_DEVICE_NAME,
            "manufacturer": "Landbook",
            "model": self.parent_pk,
            "serial_number": self.parent_dk,
        }
        total_cfg = {
            "name": "Smart socket total power",
            "object_id": f"{MAIN_DEVICE_OBJECT_ID}_smart_socket_total_power",
            "has_entity_name": True,
            "state_topic": f"{self.base_topic}/smart_sockets/total_power",
            "unit_of_measurement": "W",
            "device_class": "power",
            "state_class": "measurement",
            "force_update": True,
            "unique_id": f"{self.parent_dk}_smart_socket_total_power",
            "device": parent_device,
            "availability_topic": self.liveness_topic,
            "payload_available": "online",
            "payload_not_available": "offline",
            "suggested_display_precision": 0,
        }
        self.publish(f"homeassistant/sensor/{self.parent_dk}/smart_socket_total_power/config", json.dumps(total_cfg), retain=True)

        for dev in self.devices.values():
            dk = str(dev["device_key"])
            slug = slugify(dk)
            availability_topic = f"{self.base_topic}/smart_sockets/{dk}/availability"
            availability = [
                {"topic": self.liveness_topic, "payload_available": "online", "payload_not_available": "offline"},
                {"topic": availability_topic, "payload_available": "online", "payload_not_available": "offline"},
            ]
            device = self.device_info(dev)
            self.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
            self.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
            switch_cfg = {
                "name": "Switch",
                "object_id": f"wonderfree_socket_{slug}_device_switch",
                "has_entity_name": True,
                "state_topic": f"{self.base_topic}/smart_sockets/{dk}/switch",
                "command_topic": f"{self.base_topic}/smart_sockets/{dk}/set/switch",
                "payload_on": "ON",
                "payload_off": "OFF",
                "state_on": "ON",
                "state_off": "OFF",
                "optimistic": False,
                "icon": "mdi:power-socket-eu",
                "unique_id": f"wonderfree_socket_{dk}_device_switch",
                "device": device,
                "availability": availability,
                "availability_mode": "all",
            }
            self.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", json.dumps(switch_cfg), retain=True)
            for sid, (name, unit, device_class, state_class, precision) in SMART_SOCKET_SENSOR_DEFS.items():
                self.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
                cfg = {
                    "name": name,
                    "object_id": f"wonderfree_socket_{slug}_device_{sid}",
                    "has_entity_name": True,
                    "state_topic": f"{self.base_topic}/smart_sockets/{dk}/{sid}",
                    "unique_id": f"wonderfree_socket_{dk}_device_{sid}",
                    "force_update": True,
                    "device": device,
                    "availability": availability,
                    "availability_mode": "all",
                    "suggested_display_precision": precision,
                }
                if unit:
                    cfg["unit_of_measurement"] = unit
                if device_class:
                    cfg["device_class"] = device_class
                if state_class:
                    cfg["state_class"] = state_class
                self.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", json.dumps(cfg), retain=True)
            self.publish(availability_topic, b"", retain=True)
            self.publish(
                availability_topic,
                "online" if bool(dev.get("online", True)) else "offline",
                retain=True,
            )
        log(f"smart socket discovery published: {len(self.devices)}")

    def remove_socket_from_ha(self, dk: str) -> None:
        self.publish(f"homeassistant/switch/wonderfree_socket_{dk}_device/switch/config", b"", retain=True)
        self.publish(f"homeassistant/switch/wonderfree_socket_{dk}/switch/config", b"", retain=True)
        self.publish(f"homeassistant/binary_sensor/wonderfree_socket_{dk}/power_state/config", b"", retain=True)
        for sid in SMART_SOCKET_SENSOR_DEFS:
            self.publish(f"homeassistant/sensor/wonderfree_socket_{dk}_device/{sid}/config", b"", retain=True)
            self.publish(f"homeassistant/sensor/wonderfree_socket_{dk}/{sid}/config", b"", retain=True)
        self.publish(f"{self.base_topic}/smart_sockets/{dk}/availability", "offline", retain=True)

    def fetch_socket_attrs(self, dev: dict[str, Any]) -> dict[str, Any]:
        j = self.cloud.request_json(
            "/v2/binding/enduserapi/getDeviceBusinessAttributes",
            {"dk": dev["device_key"], "pk": dev["product_key"]},
        )
        if j.get("code") != 200:
            return {}
        data = j.get("data") or {}
        attrs = data.get("customizeTslInfo") or []
        out: dict[str, Any] = {}
        for item in attrs:
            if not isinstance(item, dict):
                continue
            code = str(item.get("resourceCode") or "")
            value = item.get("resourceValce")
            if code == "switch":
                out["switch"] = "ON" if boolish(value) else "OFF"
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
                voltage = _num(measure.get("voltage_values"))
                power = _num(measure.get("power_value"))
                current = _num(measure.get("current_value"))
                if voltage is not None:
                    out["voltage"] = round(voltage / 1000.0, 3)
                if power is not None:
                    out["power"] = round(power / 1000.0, 3)
                if current is not None:
                    out["current"] = round(current / 1000.0, 3)
                if voltage is not None and current is not None:
                    apparent = round((voltage / 1000.0) * (current / 1000.0), 3)
                    out["apparent_power"] = apparent
                    out["power_factor"] = round((power / 1000.0) / apparent, 3) if apparent > 1 and power is not None else 0
        return out

    def publish_cloud_command(self, dev: dict[str, Any], on: bool) -> None:
        token = self.cloud.ensure_token()
        accel_url = self.cloud.accel_url
        if not token or not accel_url:
            raise RuntimeError("smart socket cloud token/accel_url missing")
        parsed = urllib.parse.urlparse(accel_url)
        if parsed.scheme not in ("ws", "wss"):
            raise RuntimeError(f"invalid smart socket accel_url: {accel_url}")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/ws/v2"
        prefix = self.cloud.accel_client or "qu_landbook_"
        if not prefix.endswith("_"):
            prefix += "_"
        dk = str(dev["device_key"])
        seq = (int(self.seq_by_dk.get(dk, int(time.time() * 1000) & 0xFF)) + 1) & 0xFF
        self.seq_by_dk[dk] = seq
        payload = smart_socket_frame(seq, on)
        cli = mqtt.Client(client_id=f"{prefix}{int(time.time() * 1000)}", transport="websockets", protocol=mqtt.MQTTv311)
        cli.username_pw_set(username="", password=normalize_auth(token))
        cli.ws_set_options(path=path)
        if parsed.scheme == "wss":
            cli.tls_set()
        connected = threading.Event()
        connect_result: dict[str, Any] = {}

        def on_connect(_client, _userdata, _flags, rc, *args) -> None:
            connect_result["rc"] = rc
            connected.set()

        cli.on_connect = on_connect
        cli.connect(host, port, keepalive=25)
        cli.loop_start()
        try:
            if not connected.wait(8):
                raise RuntimeError("smart socket cloud MQTT connect timeout")
            rc = int(connect_result.get("rc", -1))
            if rc != 0:
                raise RuntimeError(f"smart socket cloud MQTT connect failed rc={rc}")
            for topic in smart_socket_bus_topics(dev):
                info = cli.publish(topic, payload=payload, qos=1, retain=False)
                info.wait_for_publish(timeout=5)
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    raise RuntimeError(f"smart socket cloud publish failed rc={info.rc}")
        finally:
            cli.loop_stop()
            cli.disconnect()

    def handle_command(self, topic: str, payload: str) -> bool:
        prefix = f"{self.base_topic}/smart_sockets/"
        suffix = "/set/switch"
        if not topic.startswith(prefix) or not topic.endswith(suffix):
            return False
        dk = topic[len(prefix):-len(suffix)]
        state = str(payload or "").strip().upper()
        if state not in ("ON", "OFF"):
            return True
        now = time.time()
        recent_key = (dk, state)
        if now - self.command_recent.get(recent_key, 0) < 0.8:
            return True
        self.command_recent[recent_key] = now
        dev = self.devices.get(dk)
        if not dev:
            self.refresh_devices(publish=True)
            dev = self.devices.get(dk)
        if not dev:
            log(f"smart socket command ignored: unknown device {mask(dk)}", "warning")
            return True
        try:
            self.publish_cloud_command(dev, state == "ON")
            self.publish(f"{self.base_topic}/smart_sockets/{dk}/switch", state, retain=True)
            log(f"sent smart socket {mask(dk)} {state}")
        except Exception as exc:
            log(f"smart socket command failed {mask(dk)}: {exc}", "warning")
        return True

    def poll_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.publish_liveness("online")
                # Il lock protegge self.devices e basta: tenerlo anche durante le
                # chiamate HTTP al cloud (una per presa, timeout 10s) metteva in
                # coda dietro al polling i comandi ON/OFF che arrivano da HA.
                with self.lock:
                    devices = self.refresh_devices(publish=True)
                total_power = 0.0
                any_power = False
                for dev in devices:
                    dk = str(dev["device_key"])
                    online = bool(dev.get("online", True))
                    self.publish(f"{self.base_topic}/smart_sockets/{dk}/availability", "online" if online else "offline", retain=True)
                    if not online:
                        continue
                    # Una presa che da' errore non deve far saltare le altre.
                    try:
                        values = self.fetch_socket_attrs(dev)
                    except Exception as exc:
                        log(f"smart socket {mask(dk)} read failed: {exc}", "warning")
                        continue
                    if values:
                        self.publish(f"{self.base_topic}/smart_sockets/{dk}/availability", "online", retain=True)
                    for key, value in values.items():
                        self.publish(f"{self.base_topic}/smart_sockets/{dk}/{key}", format_state(value), retain=True)
                    if "power" in values:
                        any_power = True
                        total_power += float(values.get("power") or 0)
                if any_power:
                    self.publish(f"{self.base_topic}/smart_sockets/total_power", format_state(round(total_power, 3)), retain=True)
            except Exception as exc:
                log(f"smart socket poll failed: {exc}", "warning")
            interval = max(10, int(opt(self.opts, "smart_socket_poll_interval", 30) or 30))
            self.stop_event.wait(interval)

    def stop(self) -> None:
        self.stop_event.set()
        self.publish_liveness("offline")
        client = self.client
        self.client = None
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass
            try:
                client.loop_stop()
            except Exception:
                pass
