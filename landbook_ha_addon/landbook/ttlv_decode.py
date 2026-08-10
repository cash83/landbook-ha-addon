"""landbook.ttlv_decode — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    DEVICE_STATUS_LABELS,
    FAULT_CODE_LABELS,
    OFFICIAL_FAULT_CODES,
    OUTPUT_POWER_TAG,
    _dprint,
    _is_debug,
)


def _u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "big", signed=False)


def _s16_prefixed(data: bytes, off: int):
    if off < 0 or off + 3 > len(data):
        return None
    prefix = data[off]
    value = int.from_bytes(data[off + 1:off + 3], "big", signed=False)
    return -value if prefix & 0x80 else value


def _between(value, low, high):
    return value is not None and low <= value <= high


def _tag_u16(blob: bytes, tag: bytes):
    i = blob.find(tag)
    return None if i < 0 else _u16(blob, i + 2)


def _tag_prefixed_s16(blob: bytes, tag: bytes):
    i = blob.find(tag)
    return None if i < 0 else _s16_prefixed(blob, i + 2)



def _tag_battery_power_after(blob: bytes, tag: bytes, after_tag: bytes):
    after = blob.find(after_tag)
    start = after + 4 if after >= 0 else 0
    i = blob.find(tag, start)
    if i < 0 or i + 5 > len(blob):
        return None
    raw = blob[i + 2:i + 5]
    if raw[2] == 0 and raw[0] in (0x00, 0x80):
        return -raw[1] if raw[0] & 0x80 else raw[1]
    return _s16_prefixed(blob, i + 2)


def _read_compact_ttlv_int(data: bytes, pos: int, end: int):
    """Read the compact integer encoding used inside Landbook telemetry structs."""
    if pos >= end:
        return None, pos
    prefix = data[pos]
    marker = prefix & 0x7F
    # Most fields use len-1. This firmware also emits 0x09 for 2-byte values
    # such as battery voltage (observed: 00 1A 09 02 07 -> 519 -> 51.9V).
    vlen = 2 if marker == 0x09 else marker + 1
    if vlen < 1 or vlen > 8 or pos + 1 + vlen > end:
        return None, pos
    value = int.from_bytes(data[pos + 1:pos + 1 + vlen], "big", signed=False)
    if prefix & 0x80:
        value = -value
    return value, pos + 1 + vlen


def _apply_battery_data_struct(payload: bytes, out: dict) -> bool:
    """Decode top-level battery_data (id=3, tag 0x001c) from real LAN frames."""
    search_from = 0
    while True:
        idx = payload.find(b"\x00\x1c", search_from)
        if idx < 0:
            return False
        search_from = idx + 1
        if idx + 4 > len(payload):
            continue
        count = _u16(payload, idx + 2)
        if count is None or count <= 0 or count > 16:
            continue
        pos = idx + 4
        values = {}
        ok = True
        for _ in range(count):
            if pos + 3 > len(payload):
                ok = False
                break
            tag = _u16(payload, pos)
            pos += 2
            typ = tag & 0x07
            ident = tag >> 3
            if typ != 0x02:
                ok = False
                break
            value, new_pos = _read_compact_ttlv_int(payload, pos, len(payload))
            if new_pos == pos:
                ok = False
                break
            values[ident] = value
            pos = new_pos
        if not ok or len(values) < 3:
            continue

        soc = values.get(1)
        remaining = values.get(2)
        voltage_raw = values.get(3)
        power = values.get(5)
        temp = values.get(6)

        changed = False
        if _between(soc, 0, 100):
            out["battery_percentage"] = int(soc)
            changed = True
        if _between(remaining, 0, 65534):
            out["remaining_time_minutes"] = int(remaining)
            changed = True
        voltage = None
        if _between(voltage_raw, 400, 700):
            voltage = round(float(voltage_raw) / 10.0, 1)
        elif _between(voltage_raw, 40, 70):
            voltage = float(voltage_raw)
        if voltage is not None:
            out["battery_voltage"] = voltage
            changed = True
        if _between(power, -3000, 3000):
            out["battery_total_power"] = int(power)
            if voltage is not None and abs(float(voltage)) > 0:
                out["battery_current"] = round(float(power) / float(voltage), 2)
            changed = True
        if _between(temp, -40, 120):
            out["battery_temp"] = int(temp)
            changed = True
        return changed



def _ascii(data: bytes):
    if not data or any(b < 32 or b > 126 for b in data):
        return None
    return data.decode("ascii", errors="replace")


def _extract_bus_strings(payload: bytes, out: dict) -> None:
    string_fields = {
        0x00F3: "device_key",
        0x0113: "firmware_version_set",
        0x011B: "firmware_version_bms",
        0x0123: "firmware_version_mppt",
        0x012B: "firmware_version_inv",
        0x0143: "work_profile",
    }
    i = 0
    while i + 4 <= len(payload):
        fid = _u16(payload, i)
        ln = _u16(payload, i + 2)
        if fid is not None and ln is not None and 0 < ln <= 64 and i + 4 + ln <= len(payload):
            name = string_fields.get(fid)
            val = _ascii(payload[i + 4:i + 4 + ln])
            if name and val is not None:
                out[name] = val
                i += 4 + ln
                continue
        i += 1


def _extract_output_power_set(payload: bytes, out: dict) -> None:
    i = payload.find(OUTPUT_POWER_TAG.to_bytes(2, "big"))
    if i < 0:
        return

    # Commands use tag + signed-prefix + u16 (00 EA 01 00 8C for 140W).
    # Status reports from the device can use tag + plain u16 (00 EA 00 8C).
    value = _s16_prefixed(payload, i + 2) if i + 5 <= len(payload) else None
    if not (_between(value, 100, 800) and value % 10 == 0):
        value = _u16(payload, i + 2) if i + 4 <= len(payload) else None

    if _between(value, 100, 800):
        out["output_power_set"] = int(value)


def _parse_work_profile(wp: str, out: dict) -> None:
    # hmi_data_no = "device_status, field1_unknown, field2_candidate_uptime, fault_code, ..."
    #
    # ATTENZIONE: field[1] era storicamente etichettato "uptime_minutes_lan", ma
    # i dati raccolti (storico HA + TSL cloud) mostrano che NON si comporta come
    # un uptime: lo stesso valore (es. 257) è tornato identico a distanza di
    # 20+ minuti, e in altre sessioni è rimasto fisso per ore mentre field[2]
    # cresceva di 1 ogni minuto. field[1] resta pubblicato per compatibilità/
    # diagnostica ma sotto un nome neutro. field[2] è il candidato più plausibile
    # per il vero uptime in minuti (cresce in modo monotono nei log osservati) —
    # va trattato come ipotesi da confermare, non come dato certo.
    try:
        fields = wp.split(",")
        if len(fields) < 2:
            return
        status = int(fields[0])
        field1_unknown = int(fields[1])
        if 0 <= status <= 15:
            out["device_status_raw"] = status
            out["device_status"] = DEVICE_STATUS_LABELS.get(status, f"Stato {status}")
        if 0 <= field1_unknown <= 100000:
            out["hmi_field1_raw"] = field1_unknown
            # Manteniamo anche il vecchio nome per non rompere automazioni/dashboard
            # esistenti che lo referenziano, ma è deprecato: non è un uptime affidabile.
            out["uptime_minutes_lan"] = field1_unknown
        if len(fields) > 2:
            try:
                field2 = int(fields[2])
                if 0 <= field2 <= 100000:
                    out["hmi_field2_uptime_candidate"] = field2
            except ValueError:
                pass
        # field[3] puo' contenere anche stati HMI interni: accettalo come fault
        # solo se e' un codice presente nel TSL ufficiale.
        if len(fields) > 3:
            try:
                fc = int(fields[3])
                if fc in OFFICIAL_FAULT_CODES:
                    out["fault_code_raw"] = fc
                    out["fault_code"] = FAULT_CODE_LABELS.get(fc, f"Errore E{fc}")
                else:
                    out["fault_code_raw"] = 0
                    out["fault_code"] = "Normale"
            except ValueError:
                pass
    except (ValueError, IndexError):
        pass


def _extract_dc_data(payload: bytes) -> dict:
    out: dict = {}
    marker = b"\x00\x34\x00\x11"
    idx = payload.find(marker)
    if idx < 0:
        return out
    section = payload[idx + len(marker):idx + len(marker) + 96]
    field_map = {
        1: ("dc_output_power", "power"),
        2: ("usb_a1_voltage", "voltage"), 3: ("usb_a1_power", "power"),
        4: ("usb_a2_voltage", "voltage"), 5: ("usb_a2_power", "power"),
        6: ("usb_a3_voltage", "voltage"), 7: ("usb_a3_power", "power"),
        8: ("usb_a4_voltage", "voltage"), 9: ("usb_a4_power", "power"),
        10: ("typec_1_voltage", "voltage"), 11: ("typec_1_power", "power"),
        12: ("typec_2_voltage", "voltage"), 13: ("typec_2_power", "power"),
        14: ("dc12v_voltage", "voltage"), 15: ("dc12v_power", "power"),
        16: ("dc24v_voltage", "voltage"), 17: ("dc24v_power", "power"),
    }
    i = 0
    while i + 4 <= len(section):
        tag = _u16(section, i)
        value = _u16(section, i + 2)
        if tag is None or value is None:
            break
        field_id = tag >> 3
        name_kind = field_map.get(field_id)
        if name_kind is not None:
            name, kind = name_kind
            if kind == "voltage":
                if field_id == 14 and _between(value, 60, 600):
                    out[name] = round(value / 10.0, 1)
                elif field_id == 14 and value == 0:
                    out[name] = 0
                elif field_id != 14 and _between(value, 0, 1000):
                    out[name] = float(value) if value else 0
            elif _between(value, 0, 3000):
                out[name] = value
        i += 4
    for prefix in ("usb_a1", "usb_a2", "usb_a3", "usb_a4", "typec_1", "typec_2", "dc12v", "dc24v"):
        voltage = out.get(f"{prefix}_voltage")
        power = out.get(f"{prefix}_power")
        if _between(voltage, 0.1, 1000) and power is not None:
            out[f"{prefix}_current"] = round(float(power) / float(voltage), 2)
        elif power == 0:
            out[f"{prefix}_current"] = 0.0
    if "dc12v_power" in out and "dc12v_voltage" not in out:
        out["dc12v_voltage"] = 13.7
        out["dc12v_current"] = round(float(out["dc12v_power"]) / 13.7, 2)
    return out


def _extract_bms_cell_data(payload: bytes, out: dict) -> None:
    marker_idx = payload.find(b"\x01\x54")
    if marker_idx < 0:
        return
    i = marker_idx + 2
    seen_fields: set = set()
    while i + 4 <= len(payload):
        tag = _u16(payload, i)
        if tag is None:
            break
        field_id = tag >> 3
        prefix = payload[i + 2]
        if (tag & 0x07) == 0x02 and 14 <= field_id <= 17 and prefix == 0x00:
            compact_value = _u16(payload, i + 2)
            if compact_value is None:
                break
            if field_id == 15 and _between(compact_value, 0, 10000):
                out["battery_cycles"] = compact_value
            elif field_id == 16 and _between(compact_value, 0, 300):
                out["bms_allow_max_charge_current"] = float(compact_value)
            elif field_id == 17 and _between(compact_value, 0, 65535):
                out["bms_mos_status"] = compact_value
            seen_fields.add(field_id)
            i += 4
            continue
        if i + 5 > len(payload):
            break
        value = _u16(payload, i + 3)
        if value is None:
            break
        if (tag & 0x07) == 0x02 and 1 <= field_id <= 17 and prefix in (0x00, 0x01, 0x80, 0x81):
            signed_value = -value if prefix & 0x80 else value
            if 1 <= field_id <= 13:
                if _between(value, 2500, 5000):
                    out[f"battery_cell_{field_id:02d}_voltage"] = round(value / 1000.0, 3)
            elif field_id == 15 and _between(signed_value, 0, 10000):
                out["battery_cycles"] = signed_value
            elif field_id == 16 and _between(signed_value, 0, 300):
                out["bms_allow_max_charge_current"] = float(signed_value)
            elif field_id == 17 and _between(signed_value, 0, 65535):
                out["bms_mos_status"] = signed_value
            seen_fields.add(field_id)
            i += 5
            continue
        if len(seen_fields) >= 4 and field_id > 17:
            break
        i += 1


def _dc_component_power(values: dict):
    keys = (
        "usb_a1_power", "usb_a2_power", "usb_a3_power", "usb_a4_power",
        "typec_1_power", "typec_2_power", "dc12v_power", "dc24v_power",
    )
    if not any(k in values for k in keys):
        return None
    return sum(float(values.get(k) or 0) for k in keys)


def decode_bus_payload(plain: bytes) -> dict:
    out: dict = {}
    payload = plain
    is_work_profile_frame = payload.startswith(b"\x01\x4c")
    _extract_bus_strings(payload, out)
    if "work_profile" in out:
        _parse_work_profile(out["work_profile"], out)
    _extract_output_power_set(payload, out)
    if is_work_profile_frame and len(payload) >= 14:
        bms_temp = _u16(payload, 6) if _u16(payload, 4) == 0x000A else None
        inv_temp = _u16(payload, 10) if _u16(payload, 8) == 0x0012 else None
        mppt_temp = _u16(payload, 14) if _u16(payload, 12) == 0x001A else None
        if _between(bms_temp, -40, 120):
            out["temp_bms"] = bms_temp
        if _between(inv_temp, -40, 160):
            out["temp_inv"] = inv_temp
        if _between(mppt_temp, -40, 160):
            out["temp_mppt"] = mppt_temp

    _extract_bms_cell_data(payload, out)

    # Struttura PV TTLV — confermata dai payload raw cloud (q/2/.../bus):
    #   [i+0..1]  \x00\x0c  struct tag pv_data
    #   [i+2..3]  \x00\x03  3 sub-field
    #   [i+4..5]  \x00\x0a  sub-tag1: pv_total_power
    #   [i+?..?]  \x00\x1a  sub-tag2: pv_1_voltage
    # Encoding per-field in base al valore:
    #   4-byte (val < 256): [tag 2B][val 2B]            — _u16
    #   5-byte (val >= 256): [tag 2B][prefix 1B][val 2B] — _s16_prefixed
    # sub-tag2 a +8: sub-field1 4-byte (potenza<256W); a +9: 5-byte (>=256W)
    # sub-tag3 (0x0022) a +12: sub-field2 4-byte (tensione in V); a +13: 5-byte (in deci-V)
    i_pv = payload.find(b"\x00\x0c\x00\x03\x00\x0a")
    if i_pv >= 0 and i_pv + 17 <= len(payload):
        volt_offset = None
        for _voff in (8, 9):
            if _u16(payload, i_pv + _voff) == 0x001a:
                volt_offset = _voff
                break
        if volt_offset == 8:
            # sub-field 1: 4-byte
            pv_power = _u16(payload, i_pv + 6)
            if _between(pv_power, 0, 3000):
                out["pv_input_power"] = pv_power
            if pv_power and pv_power > 0:
                if _u16(payload, i_pv + 12) == 0x0022:
                    # 4-byte: V diretti, range 5-80V
                    volt_raw = _u16(payload, i_pv + 10)
                    if _between(volt_raw, 5, 80):
                        out["pv_panel_voltage"] = float(volt_raw)
                elif _u16(payload, i_pv + 13) == 0x0022:
                    # 5-byte: deci-V (x10), range 50-800
                    volt_raw = _s16_prefixed(payload, i_pv + 10)
                    if _between(volt_raw, 50, 800):
                        out["pv_panel_voltage"] = round(volt_raw / 10.0, 1)
            else:
                # pv_power == 0: pubblica esplicitamente 0V per pulire il valore
                # retained in HA (senza questo HA mostra l'ultimo valore del giorno)
                out["pv_panel_voltage"] = 0.0
        elif volt_offset == 9 and i_pv + 19 <= len(payload):
            # sub-field 1: 5-byte
            pv_power = _s16_prefixed(payload, i_pv + 6)
            if _between(pv_power, 0, 3000):
                out["pv_input_power"] = pv_power
            if pv_power and pv_power > 0:
                volt_raw = _s16_prefixed(payload, i_pv + 11)
                if _between(volt_raw, 50, 800):
                    out["pv_panel_voltage"] = round(volt_raw / 10.0, 1)
            else:
                out["pv_panel_voltage"] = 0.0
        if _is_debug() and out.get("pv_input_power", 0) > 0 and "pv_panel_voltage" not in out:
            end = min(i_pv + 24, len(payload))
            _dprint(f"pv struct raw[{i_pv}..{end}]: {payload[i_pv:end].hex(' ')} "
                    f"volt_offset={volt_offset}")

    if payload.startswith(b"\x00\x70") and len(payload) >= 24:
        dc_power = _u16(payload, 22)
        if _between(dc_power, 0, 3000):
            out["dc_output_power"] = dc_power
    t6a = payload.find(b"\x00\x6a")
    if t6a >= 0:
        t6a2 = payload.find(b"\x00\x6a", t6a + 4)
        if t6a2 >= 0:
            dc = _u16(payload, t6a2 + 2)
            if _between(dc, 0, 6000):
                out["dc_output_power"] = round(dc / 2.0)
    out.update(_extract_dc_data(payload))

    idx = payload.find(b"\x00\x14\x00\x03\x00\x12")
    ac_idx = payload.find(b"\x00\x2c\x00\x02\x00\x12")

    def decode_ac_power_block(block_idx: int) -> bool:
        if block_idx < 0 or block_idx + 19 > len(payload):
            return False
        voltage_raw = _s16_prefixed(payload, block_idx + 6)
        voltage_u16 = _u16(payload, block_idx + 6)
        section = payload[block_idx:block_idx + 28]
        power_raw = _tag_prefixed_s16(section, b"\x00\x1a")
        power_u16 = _tag_u16(section, b"\x00\x1a")
        freq = _tag_u16(section, b"\x00\x22")
        if not _between(power_raw, -10000, 10000) and _between(power_u16, 0, 3000):
            power_raw = power_u16
        voltage = None
        if _between(voltage_raw, 1500, 2700):
            voltage = round(voltage_raw / 10.0, 1)
        elif _between(voltage_u16, 150, 270):
            voltage = float(voltage_u16)
        if voltage is None:
            return False
        if _between(freq, 45, 65):
            out["grid_freq"] = freq
        if _between(power_raw, -10000, 10000):
            out["grid_voltage"] = voltage
            if power_raw < 0:
                out["ac_input_power"] = abs(power_raw)
                out["ac_output_power"] = 0
                out["grid_b_power"] = 0
            else:
                out["grid_b_power"] = power_raw
                out["ac_output_power"] = power_raw
                out["ac_input_power"] = 0
        else:
            out["grid_voltage"] = voltage
        return True

    if ac_idx >= 0 and decode_ac_power_block(ac_idx):
        pass
    elif idx >= 0 and idx + 19 <= len(payload):
        if decode_ac_power_block(idx):
            pass
        else:
            voltage_raw = _s16_prefixed(payload, idx + 6)
            voltage_u16 = _u16(payload, idx + 6)
            if voltage_raw == 0 or voltage_u16 == 0:
                is_battery_frame = b"\x00\x24" in payload
                out.pop("grid_voltage", None)
                if not is_battery_frame:
                    out["grid_voltage"] = 0
                    out["grid_freq"] = 0
                    out["grid_b_power"] = 0
                    out["ac_input_power"] = 0
                    out["ac_output_power"] = 0
    elif payload.startswith(b"\x00\x70"):
        pass

    battery_block_idx = payload.find(b"\x00\x24")
    idx = payload.find(b"\x53\x30\x00\x12", battery_block_idx if battery_block_idx >= 0 else 0)
    if battery_block_idx >= 0 and idx >= 0:
        section = payload[idx:min(len(payload), idx + 56)]
        soc = _tag_u16(section, b"\x00\x12")
        remaining = _tag_prefixed_s16(section, b"\x00\x1a")
        if not _between(remaining, 0, 100000):
            remaining = _tag_u16(section, b"\x00\x1a")
        temp = _tag_u16(section, b"\x00\x3a")
        voltage_pref = _tag_prefixed_s16(section, b"\x00\x22")
        voltage_u16 = _tag_u16(section, b"\x00\x22")
        power_pref = _tag_battery_power_after(section, b"\x00\x32", b"\x00\x22")
        voltage = None
        if voltage_pref is not None:
            voltage = round(voltage_pref / 10.0, 1) if voltage_pref > 200 else float(voltage_pref)
        if not _between(voltage, 40.0, 70.0) and _between(voltage_u16, 40, 70):
            voltage = float(voltage_u16)
        if _between(soc, 0, 100) and _between(temp, -40, 120):
            out["battery_percentage"] = soc
            if remaining is not None:
                out["remaining_time_minutes"] = remaining
            out["battery_temp"] = temp
            if _between(voltage, 40.0, 70.0):
                out["battery_voltage"] = float(voltage)
                if _between(power_pref, -3000, 3000):
                    out["battery_total_power"] = power_pref
                    if abs(float(voltage)) > 0:
                        out["battery_current"] = round(power_pref / float(voltage), 2)

    _apply_battery_data_struct(payload, out)

    if any(k in out for k in ("pv_input_power", "ac_input_power")):
        out["total_input_power"] = round(float(out.get("pv_input_power") or 0) + float(out.get("ac_input_power") or 0), 2)
    if any(k in out for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
        out["total_output_power"] = calculate_total_output_power(out)
    hfr_tag = payload.find(b"\x00\x9A")
    if hfr_tag >= 0 and hfr_tag + 4 <= len(payload):
        hfr_labels = {
            0: "Infrequente",
            1: "LAN HFR",
            2: "WiFi HFR",
            3: "LAN+WiFi HFR",
        }
        hfr_val = payload[hfr_tag + 3]
        if hfr_val in hfr_labels:
            out["high_frequency_reporting"] = hfr_labels[hfr_val]
    if is_work_profile_frame:
        out.pop("battery_temp", None)
    return {k: v for k, v in out.items() if v is not None}


# ══════════════════════════════════════════════════════════════════════════════
# MQTT client (minimal, no external dependencies)
# ══════════════════════════════════════════════════════════════════════════════


def calculate_total_output_power(values):
    grid_out = max(float(values.get("grid_b_power") or 0), 0.0)
    ac_out = max(float(values.get("ac_output_power") or 0), 0.0)
    if "dc_output_power" in values:
        dc_out = float(values.get("dc_output_power") or 0)
    else:
        dc_out = _dc_component_power(values)
        if dc_out is None:
            dc_out = 0.0
    ac_grid_total = max(grid_out, ac_out) if abs(grid_out - ac_out) <= 1 else grid_out + ac_out
    return round(ac_grid_total + dc_out, 2)


