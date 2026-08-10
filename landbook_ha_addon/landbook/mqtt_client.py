"""landbook.mqtt_client — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    MQTT_RECONNECT_COOLDOWN,
)


def _mqtt_remaining_length(length):
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def _mqtt_string(value):
    data = value.encode("utf-8")
    return len(data).to_bytes(2, "big") + data


class MqttConnectionError(RuntimeError):
    """Raised for MQTT socket failures so they are not handled as LAN errors."""


class MqttClient:
    def __init__(self, host, port, username=None, password=None,
                 client_id="landbook_lan_bridge",
                 will_topic=None, will_payload=None, will_retain=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_id = client_id
        self.will_topic = will_topic
        self.will_payload = will_payload
        self.will_retain = will_retain
        self.sock = None
        self.rx = bytearray()
        self.next_packet_id = 1
        self._subscriptions = []

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        flags = 0x02
        payload = _mqtt_string(self.client_id)
        if self.will_topic is not None and self.will_payload is not None:
            flags |= 0x04
            if self.will_retain:
                flags |= 0x20
            wp = self.will_payload.encode("utf-8") if isinstance(self.will_payload, str) else self.will_payload
            payload += _mqtt_string(self.will_topic) + len(wp).to_bytes(2, "big") + wp
        if self.username is not None:
            flags |= 0x80
            payload += _mqtt_string(self.username)
        if self.password is not None:
            flags |= 0x40
            payload += _mqtt_string(self.password)
        variable = _mqtt_string("MQTT") + b"\x04" + bytes([flags]) + (60).to_bytes(2, "big")
        self.sock.sendall(b"\x10" + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        reply = self.sock.recv(4)
        if len(reply) < 4 or reply[0] != 0x20 or reply[3] != 0:
            raise RuntimeError(f"MQTT connect failed: {reply.hex(' ')}")
        self.sock.setblocking(False)

    def publish(self, topic, payload, retain=False):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        variable = _mqtt_string(topic)
        header = bytes([0x31 if retain else 0x30])
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(header + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        except OSError as exc:
            raise MqttConnectionError(f"MQTT publish failed: {exc}") from exc

    def reconnect(self):
        """Chiude (se serve) e ricrea la connessione MQTT da zero."""
        self._last_reconnect_attempt = time.time()
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.connect()
        if self._subscriptions:
            self._send_subscribe(self._subscriptions)

    def publish_resilient(self, topic, payload, retain=False):
        """Come publish(), ma se il socket MQTT è morto (broken pipe, ecc.)
        tenta di riconnettersi e ripubblicare prima di arrendersi.

        Il primo tentativo di reconnect dopo un publish falito è sempre
        immediato: un alert critico (es. wifi_frozen) deve poter riuscire già
        al primo giro. Il cooldown si applica solo ai tentativi successivi,
        per non sprecare handshake MQTT ripetuti quando il broker è giù da
        più tempo (es. più alert consecutivi durante la stessa interruzione)."""
        try:
            self.publish(topic, payload, retain=retain)
            return True
        except Exception:
            last_attempt = getattr(self, "_last_reconnect_attempt", 0.0)
            if time.time() - last_attempt < MQTT_RECONNECT_COOLDOWN:
                raise
            self.reconnect()
            self.publish(topic, payload, retain=retain)
            return True

    def _send_subscribe(self, topics):
        packet_id = self.next_packet_id
        self.next_packet_id += 1
        variable = packet_id.to_bytes(2, "big")
        payload = b"".join(_mqtt_string(t) + b"\x00" for t in topics)
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(b"\x82" + _mqtt_remaining_length(len(variable) + len(payload)) + variable + payload)
        except OSError as exc:
            raise MqttConnectionError(f"MQTT subscribe failed: {exc}") from exc

    def subscribe(self, topics):
        topics = list(dict.fromkeys(t for t in topics if t))
        self._subscriptions = topics
        if not topics:
            return False
        self._send_subscribe(topics)
        return True

    def ping(self):
        try:
            if self.sock is None:
                raise OSError("MQTT socket is closed")
            self.sock.sendall(b"\xC0\x00")
        except OSError as exc:
            raise MqttConnectionError(f"MQTT ping failed: {exc}") from exc

    def disconnect(self):
        if self.sock is None:
            return
        try:
            self.sock.sendall(b"\xE0\x00")
        finally:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def read_messages(self):
        try:
            if self.sock is None:
                raise RuntimeError("MQTT disconnected")
            chunk = self.sock.recv(4096)
            if chunk:
                self.rx.extend(chunk)
            else:
                raise RuntimeError("MQTT disconnected")
        except BlockingIOError:
            pass
        except (OSError, RuntimeError) as exc:
            raise MqttConnectionError(f"MQTT disconnected: {exc}") from exc
        messages = []
        while True:
            if len(self.rx) < 2:
                return messages
            multiplier, value, pos = 1, 0, 1
            while True:
                if pos >= len(self.rx):
                    return messages
                byte = self.rx[pos]
                pos += 1
                value += (byte & 127) * multiplier
                if not byte & 128:
                    break
                multiplier *= 128
            end = pos + value
            if len(self.rx) < end:
                return messages
            retain = bool(self.rx[0] & 0x01)
            packet_type = self.rx[0] >> 4
            body = bytes(self.rx[pos:end])
            del self.rx[:end]
            if packet_type != 3 or len(body) < 2:
                continue
            topic_len = int.from_bytes(body[:2], "big")
            topic = body[2:2 + topic_len].decode("utf-8", errors="replace")
            payload = body[2 + topic_len:].decode("utf-8", errors="replace")
            messages.append((topic, payload, retain))


# ══════════════════════════════════════════════════════════════════════════════
# HA MQTT discovery
# ══════════════════════════════════════════════════════════════════════════════

