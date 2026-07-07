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


def _frame_dict(frame: bytes, body_len: int) -> dict:
    calc = checksum(frame[5:])
    return {
        "raw": frame,
        "len": body_len,
        "checksum": frame[4],
        "checksum_ok": calc == frame[4],
        "packet_id": int.from_bytes(frame[5:7], "big"),
        "cmd": int.from_bytes(frame[7:9], "big"),
        "payload": frame[9:],
    }


def _read_escaped_frame(buf: bytes, start: int):
    """Read one escaped LAN frame from *buf* starting at AA AA.

    Returns (frame_dict_or_none, raw_end, incomplete). raw_end is an index in the
    original escaped stream, so callers can safely keep only the unconsumed tail.
    The older parser unescaped the whole buffer first; that was fine for viewing
    frames, but the bridge could not know how many raw bytes had been consumed
    and sometimes replayed the last complete frame after every recv().
    """
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
            frame = bytes(out[:expected_len])
            return _frame_dict(frame, body_len), i + 1, False

        # Escape rule used by the APK after the AA AA header: when an in-frame
        # byte 0xAA is followed by 0xAA or 0x55, the raw stream carries AA 55 XX.
        # If AA 55 sits at the end of the current TCP chunk, keep the partial
        # frame for the next recv() instead of treating 0x55 as real payload.
        if len(out) > 2 and buf[i] == 0xAA and i + 1 < len(buf) and buf[i + 1] == 0x55:
            if i + 2 >= len(buf):
                return None, start, True
            if buf[i + 2] in (0xAA, 0x55):
                i += 1
        i += 1
    return None, start, True


def extract_frames(buf: bytes):
    """Return (frames, tail) from an escaped LAN stream.

    *frames* are unescaped frame dictionaries, identical to iter_frames().
    *tail* is the raw escaped suffix that was not consumed because it may contain
    a partial frame/header. This is the safe API for long-running recv loops.
    """
    frames = []
    pos = 0
    while pos < len(buf):
        start = buf.find(b"\xAA\xAA", pos)
        if start < 0:
            # Keep a single trailing AA: it may become the first byte of AA AA
            # when the next TCP chunk arrives. Drop other noise to cap memory.
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


def iter_frames(buf: bytes):
    frames, _tail = extract_frames(buf)
    yield from frames


def hexs(data: bytes) -> str:
    return data.hex(" ").upper()


def recv_some(sock: socket.socket, seconds: float, quiet_after_data: float = 0.12) -> bytes:
    """Receive bytes for up to *seconds*, but return soon after data arrives.

    The older helper always waited the full timeout even when the device had
    already answered. During LAN login it was called twice with timeout=10,
    so every reconnect appeared to take ~20s. For the bridge this made a
    simple sensor-silence reconnect look like a long deep-sleep.

    We still keep a small quiet window after the last byte so split TCP chunks
    can be coalesced; incomplete LAN frames are preserved by extract_frames().
    """
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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="")
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
