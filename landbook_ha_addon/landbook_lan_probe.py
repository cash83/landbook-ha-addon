import argparse
import socket
import time


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def escape_frame(frame: bytes) -> bytes:
    # The APK inserts 0x55 between duplicated/special 0xAA bytes after the AA AA header.
    out = bytearray(frame)
    i = 2
    while i < len(out) - 1:
        if out[i] == 0xAA and out[i + 1] in (0xAA, 0x55):
            out.insert(i + 1, 0x55)
            i += 1
        i += 1
    return bytes(out)


def unescape_stream(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        out.append(data[i])
        if i >= 2 and data[i] == 0xAA and i + 2 < len(data) and data[i + 1] == 0x55 and data[i + 2] in (0xAA, 0x55):
            i += 1
        i += 1
    return bytes(out)


def encode_cmd(cmd: int, packet_id: int, payload: bytes = b"") -> bytes:
    body_len = len(payload) + 5
    frame = bytearray()
    frame += b"\xAA\xAA"
    frame += body_len.to_bytes(2, "big")
    frame += b"\x00"
    frame += packet_id.to_bytes(2, "big")
    frame += cmd.to_bytes(2, "big")
    frame += payload
    # The APK computes the checksum over packet_id + cmd + payload only.
    frame[4] = checksum(frame[5:])
    return escape_frame(bytes(frame))


def iter_frames(buf: bytes):
    data = unescape_stream(buf)
    pos = 0
    while True:
        start = data.find(b"\xAA\xAA", pos)
        if start < 0 or len(data) - start < 9:
            break
        body_len = int.from_bytes(data[start + 2 : start + 4], "big")
        end = start + 4 + body_len
        if end > len(data):
            break
        frame = data[start:end]
        calc = checksum(frame[5:])
        yield {
            "raw": frame,
            "len": body_len,
            "checksum": frame[4],
            "checksum_ok": calc == frame[4],
            "packet_id": int.from_bytes(frame[5:7], "big"),
            "cmd": int.from_bytes(frame[7:9], "big"),
            "payload": frame[9:],
        }
        pos = end


def hexs(data: bytes) -> str:
    return data.hex(" ").upper()


def recv_some(sock: socket.socket, seconds: float) -> bytes:
    sock.setblocking(False)
    end = time.time() + seconds
    chunks = []
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if chunk:
                chunks.append(chunk)
            else:
                break
        except BlockingIOError:
            time.sleep(0.05)
        except socket.timeout:
            break
    sock.setblocking(True)
    return b"".join(chunks)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.1.65")
    p.add_argument("--port", type=int, default=6607)
    p.add_argument("--timeout", type=float, default=3.0)
    args = p.parse_args()

    commands = [
        (28720, "udp_discovery_cmd_sent_over_tcp_probe"),
        (28722, "connect"),
        (28727, "heartbeat"),
        (28729, "heartbeat_config_empty_probe"),
    ]

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        sock.settimeout(args.timeout)
        print(f"connected {args.host}:{args.port}")
        initial = recv_some(sock, 1.0)
        if initial:
            print(f"< initial {len(initial)} bytes: {hexs(initial)}")
            for f in iter_frames(initial):
                print(f"  frame cmd={f['cmd']} packet={f['packet_id']} ok={f['checksum_ok']} payload={hexs(f['payload'])}")

        packet_id = 1
        for cmd, label in commands:
            frame = encode_cmd(cmd, packet_id)
            print(f"> {label} cmd={cmd} packet={packet_id}: {hexs(frame)}")
            sock.sendall(frame)
            data = recv_some(sock, 2.0)
            if data:
                print(f"< {len(data)} bytes: {hexs(data)}")
                for f in iter_frames(data):
                    print(f"  frame cmd={f['cmd']} packet={f['packet_id']} ok={f['checksum_ok']} payload={hexs(f['payload'])}")
            else:
                print("< no response")
            packet_id += 1
            time.sleep(0.5)


if __name__ == "__main__":
    main()
