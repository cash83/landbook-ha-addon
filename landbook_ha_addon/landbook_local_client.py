import argparse
import base64
import hashlib
import socket
import time

from Crypto.Cipher import AES

from landbook_lan_probe import encode_cmd, hexs, iter_frames, recv_some


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
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    encoded = bytes([len(raw) - 1]) + raw
    return ((tag_id << 3) | 2).to_bytes(2, "big") + encoded


def parse_random(payload: bytes) -> str:
    if payload[:2] != b"\x00\x0b":
        raise ValueError(f"unexpected random payload: {hexs(payload)}")
    size = int.from_bytes(payload[2:4], "big")
    return payload[4 : 4 + size].decode("ascii")


def connect_and_login(host: str, port: int, key_b64: str, timeout: float):
    key = base64.b64decode(key_b64)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(encode_cmd(28722, 1))
        data = recv_some(sock, timeout)
        random = None
        for frame in iter_frames(data):
            if frame["cmd"] == 28723:
                random = parse_random(frame["payload"])
        if not random:
            raise RuntimeError(f"no 28723 random received: {hexs(data)}")

        digest_input = key.hex() + ";" + random
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest().encode("ascii")
        sock.sendall(encode_cmd(28724, 1, tlv_bytes(2, 3, digest)))
        data = recv_some(sock, timeout)
        ok = False
        for frame in iter_frames(data):
            if frame["cmd"] == 28725 and frame["payload"].endswith(b"\x00\x00"):
                ok = True
        if not ok:
            raise RuntimeError(f"login failed: {hexs(data)}")

        return sock, key, random.encode("ascii")
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=6607)
    parser.add_argument("--key", required=True, help="LAN key (base64). Must be retrieved from the cloud and persisted by the addon.")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--seconds", type=float, default=60)
    args = parser.parse_args()

    sock, key, iv = connect_and_login(args.host, args.port, args.key, args.timeout)
    print(f"logged in to {args.host}:{args.port}, iv={iv.decode()}")

    # Same command Landbook sends after login: reporting interval 30, enable 1.
    report_payload = ttlv_number(1, 30) + ttlv_number(2, 1)
    sock.sendall(encode_cmd(28729, 1, aes_encrypt(report_payload, key, iv)))
    print(f"sent 28729 reporting request: {hexs(report_payload)}")

    start = time.time()
    last_heartbeat = 0.0
    while time.time() - start < args.seconds:
        if time.time() - last_heartbeat >= 10:
            sock.sendall(encode_cmd(28727, 1))
            last_heartbeat = time.time()

        data = recv_some(sock, 1)
        for frame in iter_frames(data):
            payload = frame["payload"]
            print(f"frame cmd={frame['cmd']} packet={frame['packet_id']} payload={hexs(payload)}")
            if payload and len(payload) % 16 == 0:
                try:
                    plain = aes_decrypt(payload, key, iv)
                    print(f"  decrypted={hexs(plain)}")
                except Exception as exc:
                    print(f"  decrypt failed: {exc}")

        time.sleep(0.2)


if __name__ == "__main__":
    main()
