"""
Probe mirata: identifica il significato dei tag nei bus ID estesi 0x002B..0x0060.
Per ogni gruppo di bus IDs cattura la risposta e decodifica tutti i tag TTLV.
Incrocia con valori noti dal bridge per identificare i sensori.
"""
import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from landbook_lan_probe import encode_cmd, hexs, iter_frames, recv_some
from landbook_local_client import aes_decrypt, aes_encrypt, connect_and_login, ttlv_number

HOST    = os.environ.get("LANDBOOK_HOST", "192.168.1.65")
PORT    = 6607
TIMEOUT = 6.0
BUS_REFRESH_TAG = 0x009A

# Tag noti dal bridge (word-pair format: tag=word, value=next_word)
KNOWN_TAGS = {
    0x00DA: "mode (0=PPS,1=Micro-Inv,2=Power Reserve)",
    0x00E0: "grid OFF state",
    0x00E1: "grid ON state",
    0x0070: "AC OFF state",
    0x0071: "AC ON state",
    0x0078: "DC OFF state",
    0x0079: "DC ON state",
    0x0138: "beep OFF",
    0x0139: "beep ON",
    0x0102: "LED value",
    0x0132: "screen (0=ON,10=OFF)",
    0x009A: "bus_refresh tag",
}

PKT_ID = [50]


def next_id():
    PKT_ID[0] += 1
    return PKT_ID[0]


def get_lan_key() -> str:
    os.environ["WF_EMAIL"] = os.environ.get("WF_EMAIL", "")
    os.environ["WF_PASSWORD"] = os.environ.get("WF_PASSWORD", "")
    os.environ["PLATFORM"] = os.environ.get("PLATFORM", "landecia")
    if not os.environ["WF_EMAIL"] or not os.environ["WF_PASSWORD"]:
        raise RuntimeError("Set WF_EMAIL and WF_PASSWORD before running this probe")
    try:
        from wf_autodiscovery import setup as autodiscovery_setup
        autodiscovery_setup(force=True)
    except Exception as e:
        pass
    lan_key_hex = os.environ.get("LAN_KEY_HEX", "").strip()
    if not lan_key_hex:
        raise RuntimeError("LAN_KEY_HEX non disponibile")
    return base64.b64encode(bytes.fromhex(lan_key_hex)).decode("ascii")


def send_bus_mask(sock, key, iv, ids):
    payload = b"".join(i.to_bytes(2, "big") for i in ids)
    sock.sendall(encode_cmd(0x0011, next_id(), aes_encrypt(payload, key, iv)))


def send_bus_refresh(sock, key, iv):
    payload = BUS_REFRESH_TAG.to_bytes(2, "big") + (3).to_bytes(2, "big")
    sock.sendall(encode_cmd(0x0013, next_id(), aes_encrypt(payload, key, iv)))


def decode_words(data: bytes) -> list:
    """Parsing semplice: sequenza di word a 2 byte."""
    words = []
    for i in range(0, len(data) - 1, 2):
        words.append(int.from_bytes(data[i:i+2], "big"))
    return words


def decode_ttlv(data: bytes) -> list:
    """Parser TTLV: (tag_id<<3)|type, [length], value."""
    results = []
    i = 0
    while i + 1 < len(data):
        header = int.from_bytes(data[i:i+2], "big")
        tag_id  = header >> 3
        typ     = header & 7
        i += 2
        if typ == 0:  # 1-byte value
            if i >= len(data): break
            results.append((tag_id, typ, data[i:i+1]))
            i += 1
        elif typ == 1:  # 2-byte value (short)
            if i + 1 >= len(data): break
            results.append((tag_id, typ, data[i:i+2]))
            i += 2
        elif typ == 2:  # variable-length number
            if i >= len(data): break
            n = data[i] + 1  # len(raw)
            i += 1
            if i + n > len(data): break
            results.append((tag_id, typ, data[i:i+n]))
            i += n
        elif typ == 3:  # bytes/string, 2-byte length
            if i + 1 >= len(data): break
            length = int.from_bytes(data[i:i+2], "big")
            i += 2
            if i + length > len(data): break
            results.append((tag_id, typ, data[i:i+length]))
            i += length
        else:
            break  # tipo sconosciuto, interrompi
    return results


def value_int(v: bytes) -> int:
    return int.from_bytes(v, "big")


def print_packet(label: str, plain: bytes):
    print(f"\n  -- {label} ({len(plain)} bytes) ------------------")

    # Approccio 1: word pairs
    words = decode_words(plain)
    interesting_words = []
    for j in range(len(words)):
        w = words[j]
        if w in KNOWN_TAGS:
            val = words[j+1] if j+1 < len(words) else "?"
            interesting_words.append(f"    WORD {w:#06x} [{KNOWN_TAGS[w]}] = {val}")
    if interesting_words:
        print("  [word-pair hits]")
        for x in interesting_words: print(x)

    # Approccio 2: TTLV
    ttlv = decode_ttlv(plain)
    print(f"  [TTLV decode] {len(ttlv)} entries:")
    for tag_id, typ, val in ttlv[:30]:  # max 30 voci
        raw_tag = (tag_id << 3) | typ
        val_hex = hexs(val)
        val_int_str = str(value_int(val)) if len(val) <= 4 else ""
        val_str = ""
        try:
            val_str = f" str={val.decode('ascii')}" if all(32 <= b < 127 for b in val) else ""
        except Exception:
            pass
        known = KNOWN_TAGS.get(raw_tag, "")
        known_str = f" ← {known}" if known else ""
        print(f"    tag={raw_tag:#06x}(id={tag_id} t={typ}) val_hex={val_hex} int={val_int_str}{val_str}{known_str}")
    if len(ttlv) > 30:
        print(f"    ... (+{len(ttlv)-30} voci)")


def collect_frames(sock, key, iv, label: str, seconds=2.5):
    data = recv_some(sock, seconds)
    frames = list(iter_frames(data))
    if not frames:
        print(f"  [{label}] nessuna risposta")
        return
    for f in frames:
        if f["cmd"] == 0x7036:
            plain = aes_decrypt(f["payload"], key, iv) if f["payload"] else b""
            print(f"  [{label}] BUS_MASK_ACK plain={hexs(plain)}")
            continue
        try:
            plain = aes_decrypt(f["payload"], key, iv)
        except Exception:
            plain = f["payload"]
        print_packet(f"{label} cmd={f['cmd']:#06x}", plain)


def main():
    print("Autodiscovery...")
    key_b64 = get_lan_key()
    print("Connect + login...")
    sock, key, iv = connect_and_login(HOST, PORT, key_b64, TIMEOUT)
    print(f"Connesso  iv={iv.decode()}")

    # --- Baseline: bus_mask standard ---
    print("\n" + "="*60)
    print("BASELINE: bus_mask standard (0x001..0x002A) + refresh")
    print("="*60)
    STD_IDS = [
        0x001E,0x0027,0x0021,0x001C,0x0020,0x0026,0x0022,0x001F,
        0x000B,0x001D,0x0010,0x0011,0x000D,0x000A,0x0005,
        0x0008,0x0009,0x0003,0x0006,0x0002,0x001B,0x0001,
        0x000F,0x000C,0x000E,0x0004,0x0012,0x0029,0x002A,
    ]
    report_payload = ttlv_number(1, 10) + ttlv_number(2, 1)
    sock.sendall(encode_cmd(28729, next_id(), aes_encrypt(report_payload, key, iv)))
    send_bus_mask(sock, key, iv, STD_IDS)
    send_bus_refresh(sock, key, iv)
    collect_frames(sock, key, iv, "STD", seconds=3.0)

    # --- Extended: 0x002B..0x0060 a gruppi di 5 ---
    print("\n" + "="*60)
    print("EXTENDED bus IDs 0x002B..0x0060 a gruppi di 5")
    print("="*60)
    for start in range(0x002B, 0x0061, 5):
        group = list(range(start, min(start+5, 0x0061)))
        group_str = f"0x{group[0]:04X}..0x{group[-1]:04X}"
        print(f"\n--- Gruppo {group_str} ---")
        send_bus_mask(sock, key, iv, group)
        send_bus_refresh(sock, key, iv)
        collect_frames(sock, key, iv, group_str, seconds=2.0)

    sock.close()
    print("\nProbe completata.")


if __name__ == "__main__":
    main()
