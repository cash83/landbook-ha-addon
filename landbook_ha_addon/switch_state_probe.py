"""
Probe per scoprire il comando LAN di lettura stati switch.
Strategia:
  1. Autodiscovery → ottieni LAN key
  2. Connect + login al device
  3. Guarda frame spontanei subito dopo login (prima di qualsiasi subscription)
  4. Prova bus_mask con ID estesi (0x002B..0x0060) + bus_refresh → cerca switch states
  5. Prova cmd 0x0012 con i tag switch noti → potrebbe essere il "read" cmd
  6. Prova bus_mask con i tag switch stessi come bus ID
NON invia comandi che cambiano stato (scrive solo 0x0012 o ID neutri).
"""
import base64
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from landbook_lan_probe import encode_cmd, hexs, iter_frames, recv_some
from landbook_local_client import (
    aes_decrypt, aes_encrypt, connect_and_login, ttlv_number
)

HOST    = os.environ.get("LANDBOOK_HOST", "192.168.1.65")
PORT    = 6607
TIMEOUT = 6.0

# Switch state tags we want to read
SWITCH_TAGS = {
    "grid":         [0x00E0, 0x00E1],
    "ac":           [0x0070, 0x0071],
    "dc":           [0x0078, 0x0079],
    "beep":         [0x0138, 0x0139],
    "led":          [0x0102],
    "screen":       [0x0132],
}

BUS_REFRESH_TAG = 0x009A

# ── Helpers ──────────────────────────────────────────────────────────────────

def get_lan_key() -> str:
    """Esegui autodiscovery e restituisci LAN key in base64."""
    os.environ["WF_EMAIL"] = os.environ.get("WF_EMAIL", "")
    os.environ["WF_PASSWORD"] = os.environ.get("WF_PASSWORD", "")
    os.environ["PLATFORM"] = os.environ.get("PLATFORM", "landecia")
    if not os.environ["WF_EMAIL"] or not os.environ["WF_PASSWORD"]:
        raise RuntimeError("Set WF_EMAIL and WF_PASSWORD before running this probe")
    try:
        from wf_autodiscovery import setup as autodiscovery_setup
        autodiscovery_setup(force=True)
    except SystemExit as e:
        print(f"Autodiscovery SystemExit: {e}")
    except Exception as e:
        print(f"Autodiscovery error: {e}")
    lan_key_hex = os.environ.get("LAN_KEY_HEX", "").strip()
    if not lan_key_hex:
        raise RuntimeError("LAN_KEY_HEX non disponibile dopo autodiscovery")
    key_b64 = base64.b64encode(bytes.fromhex(lan_key_hex)).decode("ascii")
    print(f"[KEY] LAN key ottenuta: {key_b64}")
    return key_b64


def send_bus_mask(sock, key, iv, ids: list) -> None:
    payload = b"".join(i.to_bytes(2, "big") for i in ids)
    frame = encode_cmd(0x0011, 99, aes_encrypt(payload, key, iv))
    sock.sendall(frame)


def send_bus_refresh(sock, key, iv, mode: int = 3) -> None:
    payload = BUS_REFRESH_TAG.to_bytes(2, "big") + mode.to_bytes(2, "big")
    frame = encode_cmd(0x0013, 98, aes_encrypt(payload, key, iv))
    sock.sendall(frame)


def recv_and_print(sock, key, iv, label: str, seconds: float = 2.0) -> list:
    data = recv_some(sock, seconds)
    frames = list(iter_frames(data))
    if not frames:
        print(f"  [{label}] nessuna risposta")
        return []
    for f in frames:
        try:
            plain = aes_decrypt(f["payload"], key, iv)
        except Exception:
            plain = f["payload"]
        print(f"  [{label}] cmd={f['cmd']:#06x} packet={f['packet_id']} "
              f"raw={hexs(f['payload'][:24])}{'...' if len(f['payload'])>24 else ''}")
        print(f"           plain={hexs(plain[:48])}{'...' if len(plain)>48 else ''}")
    return frames


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("STEP 1: Autodiscovery LAN key")
    print("=" * 60)
    key_b64 = get_lan_key()

    print()
    print("=" * 60)
    print("STEP 2: Connect + login")
    print("=" * 60)
    sock, key, iv = connect_and_login(HOST, PORT, key_b64, TIMEOUT)
    print(f"Connesso a {HOST}:{PORT}  iv={iv.decode()}")

    # ── STEP 3: frame spontanei subito dopo login (no subscription) ──────────
    print()
    print("=" * 60)
    print("STEP 3: Frame spontanei dopo login (attesa 3s)")
    print("=" * 60)
    recv_and_print(sock, key, iv, "spontaneo", seconds=3.0)

    # ── STEP 4: subscription standard + bus_refresh base ────────────────────
    print()
    print("=" * 60)
    print("STEP 4: Subscription report + bus_mask standard + bus_refresh")
    print("=" * 60)
    report_payload = ttlv_number(1, 10) + ttlv_number(2, 1)
    sock.sendall(encode_cmd(28729, 2, aes_encrypt(report_payload, key, iv)))

    STD_IDS = [
        0x001E, 0x0027, 0x0021, 0x001C, 0x0020, 0x0026, 0x0022, 0x001F,
        0x000B, 0x001D, 0x0010, 0x0011, 0x000D, 0x000A, 0x0005,
        0x0008, 0x0009, 0x0003, 0x0006, 0x0002, 0x001B, 0x0001,
        0x000F, 0x000C, 0x000E, 0x0004, 0x0012, 0x0029, 0x002A,
    ]
    send_bus_mask(sock, key, iv, STD_IDS)
    send_bus_refresh(sock, key, iv, mode=3)
    recv_and_print(sock, key, iv, "std-refresh", seconds=3.0)

    # ── STEP 5: bus_mask con ID estesi 0x002B..0x0060 ────────────────────────
    print()
    print("=" * 60)
    print("STEP 5: bus_mask ID estesi 0x002B..0x0060 + bus_refresh")
    print("=" * 60)
    EXT_IDS = list(range(0x002B, 0x0061))
    send_bus_mask(sock, key, iv, EXT_IDS)
    send_bus_refresh(sock, key, iv, mode=3)
    recv_and_print(sock, key, iv, "ext-refresh", seconds=3.0)

    # ── STEP 6: bus_mask con TAG degli switch come bus ID ────────────────────
    print()
    print("=" * 60)
    print("STEP 6: bus_mask con switch tag ID come bus ID + bus_refresh")
    print("=" * 60)
    TAG_IDS = [0x00E0, 0x00E1, 0x0070, 0x0071, 0x0078, 0x0079,
               0x0138, 0x0139, 0x0102, 0x0132]
    send_bus_mask(sock, key, iv, TAG_IDS)
    send_bus_refresh(sock, key, iv, mode=3)
    recv_and_print(sock, key, iv, "tag-refresh", seconds=3.0)

    # ── STEP 7: cmd 0x0012 con ogni tag switch (possibile "read" cmd) ────────
    print()
    print("=" * 60)
    print("STEP 7: cmd 0x0012 con switch tags (possibile READ cmd)")
    print("=" * 60)
    pkt = 10
    all_tags = []
    for name, tags in SWITCH_TAGS.items():
        all_tags.append((name, tags[0]))   # usa il tag "base" (OFF/id)

    for name, tag in all_tags:
        payload = tag.to_bytes(2, "big")
        frame = encode_cmd(0x0012, pkt, aes_encrypt(payload, key, iv))
        sock.sendall(frame)
        pkt += 1
        time.sleep(0.1)
    recv_and_print(sock, key, iv, "cmd0012", seconds=3.0)

    # ── STEP 8: cmd 0x0015 con switch tags (altro possibile cmd query) ───────
    print()
    print("=" * 60)
    print("STEP 8: cmd 0x0015 con switch tags")
    print("=" * 60)
    for name, tag in all_tags:
        payload = tag.to_bytes(2, "big")
        frame = encode_cmd(0x0015, pkt, aes_encrypt(payload, key, iv))
        sock.sendall(frame)
        pkt += 1
        time.sleep(0.1)
    recv_and_print(sock, key, iv, "cmd0015", seconds=3.0)

    # ── STEP 9: bus_mask range alto 0x0060..0x00FF ───────────────────────────
    print()
    print("=" * 60)
    print("STEP 9: bus_mask ID 0x0060..0x00FF + bus_refresh")
    print("=" * 60)
    HIGH_IDS = list(range(0x0060, 0x0100))
    send_bus_mask(sock, key, iv, HIGH_IDS)
    send_bus_refresh(sock, key, iv, mode=3)
    recv_and_print(sock, key, iv, "high-refresh", seconds=4.0)

    sock.close()
    print()
    print("Probe completato.")


if __name__ == "__main__":
    main()
