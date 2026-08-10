"""landbook.bridge_main — split from landbook_ha_mqtt_bridge.py (behavior-identical)."""
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
    APP_VERSION,
    AVAILABILITY_HOLD,
    BROKEN_PIPE_RESTART,
    BUS_MASK_INTERVAL,
    BUS_REFRESH_MIN_GAP,
    COMMAND_DUPLICATE_WINDOW,
    COMMAND_OPPOSITE_WINDOW,
    DEVICE_KEY,
    FIRMWARE_SENSOR_IDS,
    FRAME_COHERENCE_REQUIRES_WORK_PROFILE,
    FRAME_SILENCE_TIMEOUT,
    HEARTBEAT_INTERVAL,
    INTELLIGENT_CHARGING_POWER_ID,
    MQTT_PING_INTERVAL,
    PENDING_SILENCE_ALERT_TTL,
    RECONNECT_DELAY_INIT,
    RECONNECT_DELAY_MAX,
    REPORT_RESUBSCRIBE,
    RICH_ALERT_COOLDOWN,
    RICH_ALERT_MAX_ATTEMPTS,
    RICH_STALE_OFFLINE_AFTER,
    RICH_TELEMETRY_ALERT,
    RICH_TELEMETRY_MARKERS,
    RXDUMP_EVERY,
    SENSOR_SILENCE_RESTART,
    STRUCT_SCALAR_JUNK_KEYS,
    SWITCH_HEX,
    UNREACHABLE_GIVEUP_RECONNECT_DELAY,
    UNREACHABLE_RESTART,
    UNREACHABLE_WIFI_FROZEN_ALERT,
    WIFI_FROZEN_ALERT_AFTER,
    WIFI_FROZEN_ALERT_COOLDOWN,
    WIFI_FROZEN_STOP_AFTER,
    _dprint,
    _is_debug,
    _restart_process,
)

from landbook.tsl_busmask import (
    invalidate_bus_mask_cache,
    resolve_bus_mask_ids,
)

from landbook.ttlv_decode import (
    _extract_output_power_set,
    decode_bus_payload,
)

from landbook.mqtt_client import (
    MqttClient,
    MqttConnectionError,
)

from landbook.cache_store import (
    _device_key,
    cleanup_disabled_cache_files,
    load_lan_sensor_cache,
    save_lan_sensor_cache,
)

from landbook.watchdog import (
    _clear_recovery_state,
    _load_recovery_state,
    _save_recovery_state,
    publish_wifi_frozen_alert,
)

from landbook.smart_socket import (
    _start_socket_liveness,
)

from landbook.powerstation_commands import (
    _build_tsl_info_frame,
    _extract_intelligent_charging_power,
    _next_packet_id,
    _send_frame,
    invalidate_tsl_controls_cache,
    send_bus_mask,
    send_bus_refresh,
    send_report_subscription,
)

from landbook.sensors import (
    _has_meaningful_sensor_data,
    apply_battery_capacity_sensors,
    apply_battery_power_balance,
    apply_cell_voltage_total_fallback,
    apply_dc_sensor_zero_baseline,
    apply_derived_sensors,
    apply_device_status_correction,
    apply_explicit_switch_sensor_overrides,
    apply_grid_frequency_default,
    apply_raw_status_labels,
    apply_reported_sensor_overrides,
    apply_tsl_preferred_aliases,
    clear_retained_sensor_states,
    guard_zero_remaining_time,
    normalize_remaining_time_from_frame,
    publish_sensor_cache,
    suppress_transient_ac_zeros,
    zero_sensor_values_for_frame,
)

from landbook.command_state import (
    _command_state_allowed,
    _normalize_output_power_state_value,
    extract_reported_command_states,
    publish_inferred_command_states,
    publish_initial_command_states,
    publish_output_power_state,
    publish_reported_command_states,
)

from landbook.command_router import (
    _flush_pending_output_power,
    handle_mqtt_command,
)

from landbook.ha_discovery import (
    publish_discovery,
    subscribe_command_topics,
)


LAN_KEY_CACHE_PATH = "/data/landbook_lan_key.json"


def _persist_lan_key_cache() -> None:
    """Write the freshly-refreshed LAN key bundle to /data so the next addon restart
    skips the cloud login."""
    bundle = {
        "email":       os.environ.get("WF_EMAIL", ""),
        "platform":    os.environ.get("PLATFORM", "landbook"),
        "lan_key_hex": os.environ.get("LAN_KEY_HEX", ""),
        "device_key":  os.environ.get("DEVICE_KEY", ""),
        "product_key": os.environ.get("PRODUCT_KEY", ""),
        "saved_at":    int(time.time()),
    }
    if not bundle["lan_key_hex"] or not bundle["device_key"]:
        return
    try:
        os.makedirs(os.path.dirname(LAN_KEY_CACHE_PATH), exist_ok=True)
        with open(LAN_KEY_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(bundle, f)
    except OSError as exc:
        print(f"LAN key cache write failed: {exc}", flush=True)


def _invalidate_lan_key_cache() -> None:
    try:
        os.remove(LAN_KEY_CACHE_PATH)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"LAN key cache invalidate failed: {exc}", flush=True)


def _refresh_lan_key(args) -> bool:
    try:
        from wf_autodiscovery import setup as _setup
        _setup(force=True)
        invalidate_bus_mask_cache()
        invalidate_tsl_controls_cache()
        new_hex = os.environ.get("LAN_KEY_HEX", "").strip()
        if new_hex:
            new_key = base64.b64encode(bytes.fromhex(new_hex)).decode("ascii")
            if new_key != args.key:
                args.key = new_key
                _persist_lan_key_cache()
                print("LAN key refreshed from cloud", flush=True)
                return True
        return False
    except Exception as exc:
        print(f"LAN key refresh failed: {exc}", flush=True)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# WiFi freeze recovery
# ══════════════════════════════════════════════════════════════════════════════



def run(args):
    availability_topic = f"{args.topic}/availability"
    device_key = _device_key(args)
    mqtt = MqttClient(
        args.mqtt_host, args.mqtt_port,
        args.mqtt_user, args.mqtt_password,
        client_id=f"landbook_lan_bridge_{device_key}",
        will_topic=availability_topic,
        will_payload="offline",
        will_retain=True,
    )
    mqtt.connect()
    # Connessione MQTT dedicata alle prese (Last Will separato dalla powerstation).
    args._socket_liveness = _start_socket_liveness(args)
    print("MQTT connected; publishing discovery...", flush=True)
    publish_discovery(mqtt, args.topic, args)
    subscribe_command_topics(mqtt, args.topic, args)

    publish_initial_command_states(mqtt, args.topic, args)
    clear_retained_sensor_states(mqtt, args.topic)
    cleanup_disabled_cache_files(args)

    sensor_cache: dict = {}
    live_sensor_keys: set[str] = set()
    restored_sensor_cache = load_lan_sensor_cache(getattr(args, "battery_cache_path", "") or "")
    if restored_sensor_cache:
        sensor_cache.update(restored_sensor_cache)
        publish_sensor_cache(mqtt, args.topic, sensor_cache, set(restored_sensor_cache), args)
        print(
            f"[sensor_cache] ripristinati {len(restored_sensor_cache)} valori LAN recenti "
            f"da {args.battery_cache_path}",
            flush=True,
        )

    reconnect_delay = RECONNECT_DELAY_INIT
    unreachable_since: float | None = None
    broken_pipe_since: float | None = None
    lan_disconnected_since: float | None = None
    availability_offline_sent = False
    sensor_silence_streak = 0       # riconnessioni consecutive senza dati sensori
    sensor_silence_since: float | None = None
    session_had_sensor_data = False  # questa sessione TCP ha ricevuto almeno un dato
    last_wifi_frozen_alert = 0.0
    unreachable_alert_streak = 0    # alert LAN unreachable consecutivi
    # Watchdog telemetria ricca (deep sleep): questi DEVONO persistere tra i
    # reconnect causati dal toggle WiFi, altrimenti il conteggio tentativi si
    # azzererebbe a ogni ricollegamento e non si fermerebbe mai.
    rich_alert_streak = 0           # toggle WiFi consecutivi senza ritorno del frame ricco
    last_rich_alert = 0.0           # cooldown alert wifi_frozen per telemetria ricca
    # ...e devono sopravvivere anche ai RESTART DI PROCESSO (UNREACHABLE_RESTART
    # / broken-pipe): senza questo, ogni restart ripartiva da "tentativo 1/3".
    _rec_st = _load_recovery_state()
    if _rec_st:
        rich_alert_streak = int(_rec_st.get("rich_alert_streak", 0) or 0)
        last_rich_alert = float(_rec_st.get("last_rich_alert", 0) or 0)
        if rich_alert_streak:
            print(
                f"recovery state ripristinato dopo restart: tentativi WiFi già "
                f"fatti = {rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS}",
                flush=True,
            )
    rich_offline_sent = False       # powerstation gia' marcata offline per telemetria stale
    # 0.10.7 — qui c'era `last_real_rich_rx` (timestamp dell'ultimo frame ricco
    # non azzerato dai reconnect), introdotto in 0.10.6 e RIMOSSO: vedi la nota
    # su RICH_STALE_OFFLINE_AFTER in constants.py. Va reintrodotto SOLO insieme
    # alla separazione fra availability dei sensori e availability dei controlli.
    first_alert_at_episode = None   # timestamp del primo alert pubblicato in questo episodio di freeze
    # ── Giveup mode (0.10.1): powerstation spenta ─────────────────────────────
    # Esauriti i tentativi WiFi con la LAN hard-unreachable: niente più restart
    # di processo, powerstation offline, retry lenti. Le prese restano vive.
    giveup_mode = False
    last_retry_ping = 0.0           # keepalive MQTT nelle attese tra i retry LAN
    # Alert 'sensor_silence' in attesa di conferma: vedi PENDING_SILENCE_ALERT_TTL.
    pending_silence_alert = None

    try:
        while True:
            sock = None
            try:
                print(f"Connecting {args.device_host}:{args.device_port}...", flush=True)
                args._lan_packet_id = 1   # reset prima del login (Bug 6 fix)
                sock, key, iv = connect_and_login(
                    args.device_host, args.device_port, args.key,
                    float(getattr(args, "timeout", 10) or 10),
                )
                # ── Connected ────────────────────────────────────────────────
                if lan_disconnected_since is not None:
                    print(f"LAN recovered after {time.time() - lan_disconnected_since:.0f}s", flush=True)
                # Il device si e' dimostrato RAGGIUNGIBILE: se avevamo un alert
                # 'sensor_silence' in sospeso (zero byte per 30s), ora sappiamo che
                # non era una powerstation spenta ma un freeze vero → lo pubblichiamo.
                if pending_silence_alert is not None:
                    _psa = pending_silence_alert
                    pending_silence_alert = None
                    _psa_now = time.time()
                    if rich_alert_streak >= RICH_ALERT_MAX_ATTEMPTS:
                        # 0.10.3: budget UNICO di RICH_ALERT_MAX_ATTEMPTS toggle per
                        # episodio, condiviso da tutti i rami (rich_telemetry_stale,
                        # lan_unreachable, sensor_silence). Esaurito il budget non si
                        # pubblica piu' nulla: il bridge continua solo a riprovare in
                        # LAN. Il contatore si azzera al ritorno della telemetria ricca.
                        print(
                            f"alert wifi_frozen (sensor_silence) NON pubblicato: "
                            f"tentativi esauriti {rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS} "
                            "in questo episodio",
                            flush=True,
                        )
                    elif _psa_now - _psa["at"] <= PENDING_SILENCE_ALERT_TTL:
                        try:
                            publish_wifi_frozen_alert(
                                mqtt, args.topic,
                                reason="sensor_silence",
                                streak=rich_alert_streak + 1,
                                duration=_psa["duration"],
                            )
                            rich_alert_streak += 1
                            last_rich_alert = _psa_now
                            last_wifi_frozen_alert = _psa_now
                            _save_recovery_state(rich_alert_streak, last_rich_alert)
                            if first_alert_at_episode is None:
                                first_alert_at_episode = _psa_now
                            print(
                                f"MQTT wifi_frozen alert pubblicato, tentativo "
                                f"{rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS}: "
                                "device raggiungibile, freeze confermato",
                                flush=True,
                            )
                        except Exception as _me:
                            print(f"MQTT wifi_frozen publish failed: {_me}", flush=True)
                    else:
                        print(
                            f"alert wifi_frozen in sospeso scaduto dopo "
                            f"{_psa_now - _psa['at']:.0f}s: scartato",
                            flush=True,
                        )
                if giveup_mode:
                    # Powerstation riaccesa dopo la rinuncia: si riparte pulito
                    # (retry veloci, contatore toggle azzerato, availability
                    # 'online' pubblicata poco piu' sotto).
                    giveup_mode = False
                    rich_alert_streak = 0
                    last_rich_alert = 0.0
                    _clear_recovery_state()
                    print(
                        "PowerStation di nuovo raggiungibile: esco dalla modalita' "
                        "rinuncia (retry rapidi, contatore toggle WiFi azzerato)",
                        flush=True,
                    )
                unreachable_since = None
                unreachable_alert_streak = 0
                # broken_pipe_since NON viene resettato qui: il TCP connect può
                # riuscire e poi dare subito Broken pipe (firmware non pronto).
                # Viene resettato solo quando arrivano dati sensori reali.
                reconnect_delay = RECONNECT_DELAY_INIT
                lan_disconnected_since = None
                availability_offline_sent = False
                session_had_sensor_data = False
                # Reset stato pendente dalla sessione precedente (Bug 2 fix):
                # evita comandi indesiderati su device appena riconnesso
                args._pending_output_power  = None
                args._pending_output_power_due = 0
                args._next_bus_kick         = 0
                args._cmd_grace_until       = 0  # reset grace period su riconnessione
                # Il TCP e' tornato: nel caso normale si riparte da 'online', cosi'
                # i controlli restano usabili durante tutto il ciclo di recupero.
                #
                # UNICA eccezione (0.10.8): se eravamo gia' andati offline per freeze
                # ostinato (3 toggle falliti), NON si torna online qui. Il connect
                # prova solo che il modulo WiFi risponde, non che il reporting sia
                # ripartito, e senza questa eccezione il primo reconnect annullerebbe
                # l'offline appena pubblicato. A rimettere 'online' ci pensa il
                # ritorno di un frame ricco vero, piu' sotto.
                # NB: in 0.10.6 questa stessa riga era gated allo stesso modo, ma
                # allora rich_offline_sent diventava True gia' dopo 40s di silenzio,
                # cioe' anche nei freeze normali → controlli morti. Ora il flag si
                # alza solo nello stato davvero bloccato, quindi il gate e' innocuo.
                if not rich_offline_sent:
                    mqtt.publish(availability_topic, "online", retain=True)
                else:
                    print(
                        "LAN riconnessa ma freeze ancora ostinato (3 toggle falliti): "
                        "powerstation resta offline finche' non torna telemetria vera",
                        flush=True,
                    )
                print(f"LAN connected; MQTT at {args.mqtt_host}:{args.mqtt_port}", flush=True)

                args._lan_packet_id = 1
                time.sleep(1.0)  # grace period post-login prima dei comandi
                send_report_subscription(sock, key, iv, args)
                sent_mask_ids = resolve_bus_mask_ids(args)
                send_bus_mask(sock, key, iv, args, ids=sent_mask_ids)
                send_bus_refresh(sock, key, iv, args)          # sollecito reporting
                last_bus_refresh_sent = time.time()

                # ── Nudge LAN+WiFi High Frequency Reporting al login ───────────
                # Invio singolo (non ripetuto) per provare a far partire la sessione
                # in modalità alta frequenza, invece di aspettare che il device la
                # scelga da solo. Valore 3 = LAN + Wi-Fi (verificato empiricamente:
                # il valore 1 "solo LAN" è un no-op su questo firmware, non sveglia
                # il device — solo 3 lo stimola davvero). Non viene mai re-inviato
                # durante la sessione anche se il device torna in Low da solo (per
                # non rincorrerlo).
                try:
                    # HFR è esposto come sensore (non più select): l'info TSL per il
                    # nudge è conservata a parte in publish_discovery.
                    _hfr_info = getattr(args, "_hfr_nudge_info", None)
                    if _hfr_info:
                        _hfr_frame = _build_tsl_info_frame(
                            _hfr_info, 3, key, iv, args, default_type="ENUM"
                        )
                        _send_frame(sock, args, _hfr_frame)
                        _dprint("sent high_frequency_reporting=3 (LAN+WiFi) one-shot al login", flush=True)
                    else:
                        _dprint("high_frequency_reporting non trovato nel TSL: nudge saltato", flush=True)
                except Exception as _hfr_exc:
                    _dprint(f"high_frequency_reporting nudge fallito: {_hfr_exc}", flush=True)

                # ── Drain comandi MQTT stantii ────────────────────────────────
                # Il broker MQTT mantiene la connessione attiva durante i disconnect
                # LAN: i comandi inviati dall'utente in HA si accumulano nel buffer
                # rx e verrebbero eseguiti tutti in sequenza appena il device torna
                # online, causando comportamenti caotici (grid ON→OFF→ON→OFF).
                # Scartiamo per ~1s qualsiasi comando accodato durante il disconnect.
                _drain_end = time.time() + float(getattr(args, "mqtt_stale_drain_seconds", 2.0) or 2.0)
                _drained = 0
                while time.time() < _drain_end:
                    for _t, _p, _r in mqtt.read_messages():
                        if not _r:
                            _drained += 1
                            _dprint(f"discarded stale MQTT command: {_t}={_p}", flush=True)
                    time.sleep(0.05)
                if _drained:
                    print(f"drained {_drained} stale MQTT command(s) after reconnect", flush=True)

                now = time.time()
                last_heartbeat = now
                last_mqtt_ping = now
                last_frame_rx = now
                last_sensor_rx = now
                last_rich_rx = now   # watchdog telemetria ricca (work_profile) — per-connessione
                next_resubscribe  = now + REPORT_RESUBSCRIBE if REPORT_RESUBSCRIBE > 0 else 0
                next_bus_mask     = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0
                last_bus_refresh_sent = now  # debounce: evita invii bus_mask/bus_refresh troppo ravvicinati
                recv_buf = b""

                while True:
                    now = time.time()

                    # Nessun frame grezzo → device/WiFi in deep-sleep
                    if now - last_frame_rx >= FRAME_SILENCE_TIMEOUT:
                        raise RuntimeError(
                            f"no frames for {now - last_frame_rx:.0f}s — reconnecting"
                        )

                    # NOTA (0.9.34): qui c'era un secondo watchdog "no sensor data for
                    # SENSOR_RECONNECT_AFTER (50s)". Era CODICE MORTO: last_sensor_rx e
                    # last_frame_rx vengono aggiornati dallo stesso `if data:` (vedi sotto),
                    # quindi sono sempre identici, e il watchdog "no frames" (30s) scattava
                    # sempre 20s prima rendendolo irraggiungibile. In piu' il device, durante
                    # il deep sleep, continua a mandare frame VUOTI (pv_data struct a 0
                    # elementi) che aggiornavano comunque il timestamp: il freeze reale non
                    # veniva mai visto da qui. Il freeze e' coperto da:
                    #   - "no frames" 30s        → LAN davvero morta (zero byte)
                    #   - watchdog telemetria RICCA → device vivo ma muto (sotto)
                    _grace_until = getattr(args, "_cmd_grace_until", 0) or 0

                    # Watchdog telemetria RICCA: la powerstation è in deep sleep
                    # (WiFi connesso ma reporting ricco fermo, arrivano solo frame
                    # minimi). Un nuovo login LAN NON la sveglia: serve il toggle del
                    # WiFi del router. Pubblichiamo wifi_frozen → l'automazione HA
                    # ricicla il WiFi e la risveglia. Al massimo RICH_ALERT_MAX_ATTEMPTS
                    # tentativi: se dopo N toggle il frame ricco non torna, RINUNCIAMO
                    # (NON spegniamo l'addon → prese e frame minimi restano vivi). Il
                    # conteggio riparte da 0 appena torna un frame ricco.
                    # Rispetta la grace post-comando.
                    # La condizione "i frame minimi STANNO arrivando" e' resa
                    # esplicita (`now - last_frame_rx < FRAME_SILENCE_TIMEOUT`):
                    # oggi e' gia' garantita dalla raise "no frames" qui sopra, che
                    # esce dal loop, ma scriverla qui rende la regola leggibile e
                    # impedisce che un domani, spostando o condizionando quella
                    # raise, l'alert cominci a partire anche a device muto — cioe'
                    # proprio il falso positivo che si vuole evitare.
                    if RICH_TELEMETRY_ALERT > 0 and now - last_rich_rx >= RICH_TELEMETRY_ALERT \
                            and now - last_frame_rx < FRAME_SILENCE_TIMEOUT \
                            and now >= _grace_until \
                            and rich_alert_streak < RICH_ALERT_MAX_ATTEMPTS \
                            and (last_rich_alert == 0
                                 or now - last_rich_alert >= RICH_ALERT_COOLDOWN):
                        try:
                            publish_wifi_frozen_alert(
                                mqtt, args.topic,
                                reason="rich_telemetry_stale",
                                streak=rich_alert_streak + 1,
                                duration=now - last_rich_rx,
                            )
                            rich_alert_streak += 1
                            print(
                                f"telemetria ricca assente da {now - last_rich_rx:.0f}s "
                                f"(powerstation in deep sleep?) → wifi_frozen pubblicato, "
                                f"tentativo {rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS} "
                                "(toggle WiFi router)",
                                flush=True,
                            )
                            if rich_alert_streak >= RICH_ALERT_MAX_ATTEMPTS:
                                print(
                                    f"telemetria ricca ancora assente dopo {RICH_ALERT_MAX_ATTEMPTS} "
                                    "tentativi WiFi: RINUNCIO. Add-on NON spento (prese e frame "
                                    "minimi restano attivi); riprovo appena torna un frame ricco.",
                                    flush=True,
                                )
                        except Exception as _rexc:
                            print(f"MQTT wifi_frozen (rich stale) publish failed: {_rexc}", flush=True)
                        last_rich_alert = now
                        _save_recovery_state(rich_alert_streak, last_rich_alert)

                    # ── Powerstation OFFLINE dopo i 3 toggle falliti (0.10.8) ──
                    # Il TCP è vivo (arrivano i frame minimi da 4 byte), quindi il
                    # ramo delle eccezioni non scatta mai e i sensori resterebbero
                    # con l'ULTIMO valore ricevuto: HA mostrerebbe per ore un
                    # "Total Output Power 101 W" fantasma mentre il device è muto.
                    #
                    # Ma NON si va offline al primo freeze: dal 1o e dal 2o toggle
                    # il device si riprende sempre, e siccome availability vale per
                    # tutto il DEVICE (sensori E controlli), farlo sparire li'
                    # significherebbe solo rendere non comandabile una powerstation
                    # che risponde ancora. Si aspetta quindi che il budget di
                    # RICH_ALERT_MAX_ATTEMPTS toggle sia esaurito E che anche
                    # l'ultimo abbia avuto la sua finestra (RICH_STALE_OFFLINE_AFTER
                    # dall'ultimo alert): solo allora il freeze e' davvero ostinato.
                    # rich_alert_streak torna a 0 al primo frame ricco, quindi questa
                    # condizione non puo' essere vera durante un recupero riuscito.
                    # L'add-on resta in piedi: le prese hanno availability separata.
                    # Il vincolo su last_rich_rx (per-connessione) evita il lampo di
                    # 'unavailable' subito dopo un restart o un reconnect avvenuto
                    # mentre lo streak ripristinato da /data era gia' a 3/3: prima di
                    # dichiarare offline si concedono comunque RICH_TELEMETRY_ALERT
                    # secondi di silenzio osservati IN QUESTA sessione.
                    if RICH_TELEMETRY_ALERT > 0 \
                            and rich_alert_streak >= RICH_ALERT_MAX_ATTEMPTS \
                            and last_rich_alert \
                            and now - last_rich_alert >= RICH_STALE_OFFLINE_AFTER \
                            and now - last_rich_rx >= RICH_TELEMETRY_ALERT \
                            and now >= _grace_until \
                            and not rich_offline_sent:
                        try:
                            mqtt.publish_resilient(availability_topic, "offline", retain=True)
                            rich_offline_sent = True
                            availability_offline_sent = True
                            print(
                                f"PowerStation → offline: {RICH_ALERT_MAX_ATTEMPTS} toggle WiFi "
                                f"falliti e nessun dato reale da {now - last_rich_rx:.0f}s "
                                "(i sensori diventano unavailable invece di mostrare valori "
                                "vecchi). Prese non toccate.",
                                flush=True,
                            )
                        except Exception as _oexc:
                            print(f"MQTT powerstation offline publish failed: {_oexc}", flush=True)

                    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                        _send_frame(sock, args, encode_cmd(28727, _next_packet_id(args)))
                        last_heartbeat = now

                    if now - last_mqtt_ping >= MQTT_PING_INTERVAL:
                        mqtt.ping()
                        last_mqtt_ping = now

                    # Le prese NON vengono più pollate qui: il polling gira nel
                    # SmartSocketWorker (thread dedicato), indipendente dal loop LAN.

                    # Rinnova subscription: il device la dimentica se resta senza richiami.
                    # Anche durante il silenzio sensori continuiamo, come nel bridge 0.3.55:
                    # se blocchiamo questi richiami, la LAN resta ferma fino al recovery.
                    if REPORT_RESUBSCRIBE > 0 and now >= next_resubscribe:
                        send_report_subscription(sock, key, iv, args)
                        next_resubscribe = now + REPORT_RESUBSCRIBE

                    if BUS_MASK_INTERVAL > 0 and now >= next_bus_mask:
                        if now - last_bus_refresh_sent >= BUS_REFRESH_MIN_GAP:
                            send_bus_mask(sock, key, iv, args)
                            send_bus_refresh(sock, key, iv, args)
                            last_bus_refresh_sent = now
                        else:
                            _dprint(
                                f"bus_mask/bus_refresh periodico soppresso "
                                f"(debounce, {now - last_bus_refresh_sent:.1f}s fa)",
                                flush=True,
                            )
                        next_bus_mask = now + BUS_MASK_INTERVAL

                    for topic, payload, retained in mqtt.read_messages():
                        if retained:
                            _dprint(f"ignored retained MQTT command: {topic}={payload}", flush=True)
                            continue
                        # I comandi delle prese sono gestiti dal SmartSocketWorker
                        # su una connessione MQTT separata: qui restano solo i
                        # comandi della powerstation.
                        if not session_had_sensor_data:
                            print(f"command dropped (no sensor data yet): {topic}={payload}", flush=True)
                            continue
                        handle_mqtt_command(topic, payload, sock, mqtt, args.topic, key, iv, args)

                    if session_had_sensor_data:   # Bug 3 fix
                        _flush_pending_output_power(sock, mqtt, args.topic, key, iv, args)

                    kick_due = getattr(args, "_next_bus_kick", 0) or 0
                    if kick_due and now >= kick_due:
                        # Dopo ogni comando: bus_refresh + bus_mask completa (ids=31).
                        # Mantiene tutti i sensori attivi senza restringere la mask a batteria/base.
                        if now - last_bus_refresh_sent >= BUS_REFRESH_MIN_GAP:
                            send_bus_refresh(sock, key, iv, args)
                            send_bus_mask(sock, key, iv, args)
                            last_bus_refresh_sent = now
                        else:
                            _dprint(
                                f"bus_mask/bus_refresh post-comando soppresso "
                                f"(debounce, {now - last_bus_refresh_sent:.1f}s fa)",
                                flush=True,
                            )
                        args._next_bus_kick = 0
                        next_bus_mask = now + BUS_MASK_INTERVAL if BUS_MASK_INTERVAL > 0 else 0

                    # ── Receive and decode LAN frames ────────────────────────
                    data = recv_some(sock, 0.2)
                    if data:
                        last_frame_rx = time.time()
                        # FIX "frame grezzi": qualunque byte dal device (anche solo
                        # l'eco dell'heartbeat o un frame in modalità Low) prova che
                        # il link di reporting è VIVO. Il device oscilla Low/High da
                        # solo ~ogni 30s: durante la fase Low i sensori "meaningful"
                        # (battery_voltage…) possono mancare >50s pur continuando ad
                        # arrivare frame → il vecchio watchdog "no sensor data 50s" lo
                        # scambiava per freeze e faceva scattare l'automazione WiFi.
                        # Aggiornando qui last_sensor_rx, il freeze reale resta
                        # coperto dal watchdog "no frames 30s" (zero byte = LAN morta).
                        last_sensor_rx = last_frame_rx
                        recv_buf += data

                    if not recv_buf:
                        continue

                    frames, recv_buf = extract_frames(recv_buf)
                    if not frames and len(recv_buf) > 8192:
                        print(f"LAN recv buffer discarded ({len(recv_buf)} bytes without frame)", flush=True)
                        recv_buf = b""

                    for frame in frames:
                        raw_payload = frame.get("payload", b"")
                        if not frame.get("checksum_ok"):
                            _dprint(
                                f"ignored LAN frame with bad checksum: "
                                f"cmd={frame.get('cmd')} packet={frame.get('packet_id')}",
                                flush=True,
                            )
                            continue
                        if not raw_payload or len(raw_payload) % 16:
                            continue
                        try:
                            plain = aes_decrypt(raw_payload, key, iv)
                        except Exception:
                            continue

                        # output_power_set puo' arrivare in frame LAN di stato brevi
                        # che non contengono altri sensori: aggiorna subito lo slider.
                        lan_power_state = {}
                        _extract_output_power_set(plain, lan_power_state)
                        if "output_power_set" in lan_power_state:
                            publish_output_power_state(
                                mqtt,
                                args.topic,
                                lan_power_state["output_power_set"],
                                "LAN",
                                args,
                            )

                        charge_power = _extract_intelligent_charging_power(plain)
                        if charge_power is not None and _command_state_allowed(
                            args, INTELLIGENT_CHARGING_POWER_ID, str(charge_power)
                        ):
                            mqtt.publish(
                                f"{args.topic}/cmd_state/{INTELLIGENT_CHARGING_POWER_ID}",
                                str(charge_power),
                                retain=True,
                            )

                        decoded = decode_bus_payload(plain)
                        # ── DIAGNOSTICA frame (solo con log_level: debug) ──────
                        # Serve a distinguere DEEP SLEEP da PROBLEMA DI DECODING:
                        #  - plain corto (poche decine di byte) e decoded quasi vuoto
                        #    → il device manda davvero un frame minimo (deep sleep);
                        #  - plain LUNGO ma decoded quasi vuoto
                        #    → i dati ci sono ma il decoder non li estrae (bug parser).
                        # Rate-limit: al massimo un dump ogni RXDUMP_EVERY secondi,
                        # così il log resta leggibile anche con frame ogni 2s.
                        if _is_debug():
                            _rx_now = time.time()
                            if _rx_now - getattr(args, "_last_rxdump", 0) >= RXDUMP_EVERY:
                                args._last_rxdump = _rx_now
                                _poor = len(decoded) <= 2
                                _dprint(
                                    f"[rxdump]{' POVERO' if _poor else ' ricco'} "
                                    f"cmd={frame.get('cmd')} plain_len={len(plain)} "
                                    f"n_keys={len(decoded)} keys={sorted(decoded.keys()) if decoded else []}",
                                    flush=True,
                                )
                                # I byte grezzi solo per i frame poveri: sono quelli
                                # che dobbiamo capire (vuoti o mal decodificati?).
                                if _poor:
                                    _dprint(f"[rxdump] hex={plain.hex(' ')}", flush=True)
                        # TSL-driven walker: integra i campi ricavati dal TSL che
                        # il decoder principale non espone direttamente.
                        try:
                            from landbook_ttlv_walker import decode_payload as _ttlv_decode
                            walker_out = _ttlv_decode(plain) or {}
                        except Exception as _exc:
                            walker_out = {}
                            print(f"ttlv walker error: {_exc}", flush=True)
                        if walker_out:
                            # Non sovrascrivere campi già normalizzati in etichette
                            # leggibili, altrimenti HA oscillerebbe tra label e valore raw.
                            _LABELED_BY_LEGACY = {
                                "fault_code", "fault_code_raw",
                                "device_status", "device_status_raw",
                                "device_status_corrected",
                                "mode",
                                "high_frequency_reporting",
                            }
                            for k, v in walker_out.items():
                                if k in _LABELED_BY_LEGACY:
                                    continue
                                decoded[k] = v
                            # Alcuni codici (es. led_status_set) vengono riportati dal
                            # firmware in modo incoerente tra il frame "work_profile"
                            # completo e i frame brevi solo-batteria: nello stesso ciclo
                            # di polling l'uno dice ON, l'altro OFF. Per questi codici
                            # ci fidiamo solo del frame work_profile (quello che il
                            # firmware aggiorna in modo affidabile dopo un comando) e
                            # ignoriamo il valore quando arriva da un frame senza
                            # work_profile, invece di pubblicare ogni lettura e far
                            # sfarfallare l'entità HA tra i due stati.
                            _has_work_profile = "work_profile" in decoded
                            for _code in SWITCH_HEX:
                                if _code not in walker_out:
                                    continue
                                if _code in FRAME_COHERENCE_REQUIRES_WORK_PROFILE and not _has_work_profile:
                                    continue
                                _state = "ON" if bool(walker_out[_code]) else "OFF"
                                if _command_state_allowed(args, _code, _state):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", _state, retain=True)
                            # Translate raw int values to TSL labels for any code
                            # exposed as a HA select entity, then publish them as
                            # the entity state so HA shows the human-readable
                            # option (e.g. led_status_set=3 → "SOS").
                            #
                            # The TTLV wire format encodes "integer 0" and "bool
                            # false" with the same compact tag (and "integer 1"
                            # can collapse onto "bool true" too) — the firmware
                            # picks whichever encoding is shortest. So a BOOL
                            # value here isn't actually ambiguous: it's always
                            # literal index 0 (False) or 1 (True), regardless of
                            # how many options the ENUM has. Translate before
                            # the label lookup instead of discarding it.
                            _select_cat = getattr(args, "_tsl_select_catalog", {}) or {}
                            for _code, _info in _select_cat.items():
                                if _code not in walker_out:
                                    continue
                                if _code in FRAME_COHERENCE_REQUIRES_WORK_PROFILE and not _has_work_profile:
                                    continue
                                _opts = _info.get("options") or {}
                                _raw = walker_out[_code]
                                if isinstance(_raw, bool):
                                    _raw = 1 if _raw else 0
                                try:
                                    _label = _opts.get(int(_raw))
                                except (TypeError, ValueError):
                                    _label = None
                                if _label and _command_state_allowed(args, _code, _label):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", _label, retain=True)
                            _number_cat = getattr(args, "_tsl_number_catalog", {}) or {}
                            for _code in _number_cat:
                                if _code not in walker_out:
                                    continue
                                _nval = walker_out[_code]
                                # output_power_set can arrive as the TSL raw x10 value
                                # (e.g. 1000 for 100 W). Never publish it out of the HA
                                # number range, or HA logs "Invalid value ... (range ...)".
                                if _code == "output_power_set":
                                    _nval = _normalize_output_power_state_value(_nval)
                                    if _nval is None:
                                        continue
                                if _command_state_allowed(args, _code, str(_nval)):
                                    mqtt.publish(f"{args.topic}/cmd_state/{_code}", str(_nval), retain=True)
                        if decoded:
                            # Spazzatura struct-scalare (pv_data:0 e simili): via
                            # sempre. Un frame che resta vuoto è un keepalive del
                            # firmware in standby → scartato in silenzio.
                            for _jk in STRUCT_SCALAR_JUNK_KEYS:
                                if _jk in decoded and not isinstance(decoded[_jk], dict):
                                    decoded.pop(_jk)
                        if decoded:
                            # high_frequency_reporting NON viene più scartato: è
                            # esposto come sensore di sola lettura (vedi
                            # FORCE_SENSOR_CODES). Resta in NON_MEANINGFUL_SENSOR_KEYS,
                            # quindi non conta come "dato utile" per il watchdog.
                            if not args.show_firmware_sensors:
                                decoded = {k: v for k, v in decoded.items() if k not in FIRMWARE_SENSOR_IDS}
                            # Frame ricco (work_profile) ricevuto → resetta il watchdog
                            # telemetria ricca e il contatore tentativi, così l'alert
                            # wifi_frozen scatta solo quando il device smette DAVVERO di
                            # mandare i dati ricchi, e riparte da 0 dopo un risveglio.
                            if not RICH_TELEMETRY_MARKERS.isdisjoint(decoded):
                                last_rich_rx = time.time()
                                # Dati reali tornati: la powerstation torna online
                                # (i sensori escono da 'unavailable' con valori veri).
                                if rich_offline_sent:
                                    try:
                                        mqtt.publish_resilient(availability_topic, "online", retain=True)
                                        print("PowerStation → online: dati reali tornati", flush=True)
                                    except Exception as _onexc:
                                        print(f"MQTT powerstation online publish failed: {_onexc}", flush=True)
                                    rich_offline_sent = False
                                    availability_offline_sent = False
                                if rich_alert_streak:
                                    print(
                                        f"telemetria ricca tornata (dopo {rich_alert_streak} "
                                        "tentativo/i WiFi) — reset watchdog",
                                        flush=True,
                                    )
                                    rich_alert_streak = 0
                                # Episodio chiuso: azzera anche il cooldown, così al
                                # prossimo freeze il PRIMO wifi_frozen parte subito a
                                # RICH_TELEMETRY_ALERT (60s) e non viene ritardato.
                                last_rich_alert = 0.0
                                _clear_recovery_state()
                            if decoded:
                                meaningful_sensor_data = _has_meaningful_sensor_data(decoded, args)
                                if meaningful_sensor_data:
                                    last_sensor_rx = time.time()
                                    if "hmi_field1_raw" in decoded:
                                        args._last_field1_seen = decoded["hmi_field1_raw"]
                                    if "hmi_field2_uptime_candidate" in decoded:
                                        _new_uptime = decoded["hmi_field2_uptime_candidate"]
                                        _prev_uptime = getattr(args, "_last_uptime_seen", None)
                                        if _prev_uptime is not None and _new_uptime < _prev_uptime:
                                            # 0.10.6 — NON e' un uptime: e' il MINUTO DEL
                                            # GIORNO dell'orologio locale del device.
                                            # Verificato il 10/08 su 15 campioni in 14h,
                                            # sempre a 1-4 minuti da h*60+m dell'ora HA
                                            # (21:00→1259, 22:24→1343, 23:48→1427,
                                            # 00:30→29, 04:05→241). Il calo 1439→0 e'
                                            # quindi la MEZZANOTTE, non un reboot, e il
                                            # warning si ripeteva ogni notte. Segnaliamo
                                            # solo i cali che NON sono il rollover.
                                            _is_midnight_rollover = (
                                                _prev_uptime >= 1380 and _new_uptime <= 60
                                            )
                                            if _is_midnight_rollover:
                                                _dprint(
                                                    f"hmi_field2 {_prev_uptime} -> {_new_uptime}: "
                                                    "rollover di mezzanotte dell'orologio del "
                                                    "device (atteso, non un riavvio)",
                                                    flush=True,
                                                )
                                            else:
                                                print(
                                                    f"hmi_field2 (minuto del giorno) è SCESO "
                                                    f"({_prev_uptime} -> {_new_uptime}) fuori dal "
                                                    "rollover di mezzanotte: orologio del device "
                                                    "risincronizzato o riavvio interno",
                                                    flush=True,
                                                )
                                        args._last_uptime_seen = _new_uptime
                                    if sensor_silence_since is not None:
                                        print(
                                            f"freeze terminato dopo {last_sensor_rx - sensor_silence_since:.0f}s "
                                            f"(hmi_field1={getattr(args, '_last_field1_seen', '?')}, "
                                            f"hmi_field2_uptime_candidate={getattr(args, '_last_uptime_seen', '?')})",
                                            flush=True,
                                        )
                                    sensor_silence_since = None
                                    sensor_silence_streak = 0
                                    first_alert_at_episode = None
                                    args._cmd_grace_until = 0   # dati arrivati → grace non più necessaria
                                    if not session_had_sensor_data:
                                        session_had_sensor_data = True
                                        # Dati reali ricevuti: broken-pipe loop terminato
                                        if broken_pipe_since is not None:
                                            print(
                                                f"broken-pipe loop terminato dopo "
                                                f"{time.time() - broken_pipe_since:.0f}s — dati ricevuti",
                                                flush=True,
                                            )
                                        broken_pipe_since = None
                                else:
                                    _dprint(f"ignored non-meaningful decoded payload: {decoded}", flush=True)

                            alias_keys = apply_tsl_preferred_aliases(decoded)
                            zero_baseline_keys = apply_dc_sensor_zero_baseline(sensor_cache, decoded)
                            cell_voltage_keys = apply_cell_voltage_total_fallback(sensor_cache, decoded)
                            zero_values = zero_sensor_values_for_frame(sensor_cache, decoded)
                            if zero_values:
                                decoded.update(zero_values)
                            suppress_transient_ac_zeros(sensor_cache, decoded, args)

                            remaining_frame_keys = normalize_remaining_time_from_frame(decoded, sensor_cache)
                            guard_zero_remaining_time(decoded, sensor_cache)
                            explicit_override_keys = apply_explicit_switch_sensor_overrides(decoded, sensor_cache)
                            sensor_cache.update(decoded)
                            frame_publish_keys = set(decoded)
                            frame_publish_keys.update(remaining_frame_keys)
                            frame_publish_keys.update(alias_keys)
                            frame_publish_keys.update(zero_baseline_keys)
                            frame_publish_keys.update(cell_voltage_keys)
                            frame_publish_keys.update(explicit_override_keys)
                            apply_derived_sensors(sensor_cache)
                            frame_publish_keys.update(apply_battery_capacity_sensors(sensor_cache, decoded, args))
                            frame_publish_keys.update(apply_grid_frequency_default(sensor_cache, decoded, args))
                            if any(k in decoded for k in ("pv_input_power", "ac_input_power")):
                                frame_publish_keys.add("total_input_power")
                            if any(k in decoded for k in ("grid_b_power", "ac_output_power", "dc_output_power")):
                                frame_publish_keys.add("total_output_power")
                            frame_publish_keys.update(apply_battery_power_balance(sensor_cache, decoded, args))
                            frame_publish_keys.update(apply_device_status_correction(sensor_cache, decoded))
                            frame_publish_keys.update(apply_raw_status_labels(sensor_cache, decoded))
                            sensor_cache["updated_at"] = int(time.time())
                            # The device rotates telemetry groups: PV, BMS, DC, etc.
                            # Once a powerstation sensor has been observed on LAN in
                            # this process, refresh it on every useful LAN frame so HA
                            # keeps the whole powerstation surface live at LAN cadence.
                            live_sensor_keys.update(frame_publish_keys)
                            publish_sensor_cache(mqtt, args.topic, sensor_cache, live_sensor_keys, args)
                            save_lan_sensor_cache(args.battery_cache_path, sensor_cache, frame_publish_keys)
                            if "output_power_set" in decoded:
                                publish_output_power_state(mqtt, args.topic, decoded["output_power_set"], "LAN decoded", args)
                            publish_inferred_command_states(mqtt, args.topic, sensor_cache, decoded, args)
                            if decoded:
                                debug_decoded = dict(decoded)
                                _dprint(f"decoded: {debug_decoded}", flush=True)

                        reported = extract_reported_command_states(plain) if len(plain) <= 96 else {}
                        if reported:
                            if "output_power" in reported:
                                publish_output_power_state(mqtt, args.topic, reported["output_power"], "LAN reported", args)
                            publish_reported_command_states(mqtt, args.topic, reported, args)
                            override_keys = apply_reported_sensor_overrides(sensor_cache, reported)
                            if override_keys:
                                sensor_cache["updated_at"] = int(time.time())
                                live_sensor_keys.update(override_keys)
                                publish_sensor_cache(mqtt, args.topic, sensor_cache, live_sensor_keys, args)

            except MqttConnectionError as exc:
                print(f"MQTT error: {exc} — restarting bridge", flush=True)
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None
                try:
                    mqtt.disconnect()
                except Exception:
                    pass
                _restart_process(args)

            except (OSError, RuntimeError) as exc:
                now = time.time()
                exc_text = str(exc).lower()

                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None

                # ── WiFi freeze detection ─────────────────────────────────────
                # Silenzio sensori per 60s mentre il TCP è vivo = WiFi freeze.
                # Può accadere sia a inizio sessione (zombie puro) sia a metà
                # sessione (freeze progressivo): contiamo entrambi i casi.
                is_sensor_silence = (
                    bool(getattr(args, "freeze_detection_enabled", True)) and
                    ("no sensor data" in exc_text or "no frames" in exc_text)
                )
                exc_errno = getattr(exc, "errno", None)
                reset_errnos = {getattr(errno, "ECONNRESET", 104), 10054}
                reset_errnos.discard(None)
                is_lan_reset = (
                    exc_errno in reset_errnos or
                    isinstance(exc, ConnectionResetError) or
                    any(s in exc_text for s in (
                        "connection reset by peer",
                        "connection reset",
                        "forcibly closed",
                    ))
                )
                is_hard_unreachable = (
                    exc_errno in {errno.EHOSTUNREACH, errno.ENETUNREACH} or
                    any(s in exc_text for s in (
                        "host is unreachable",
                        "network is unreachable",
                        "no route to host",
                        "timed out",
                    ))
                )
                # Hard-unreachable = la powerstation NON c'è (spenta/staccata/rete giù).
                # Un eventuale alert 'sensor_silence' in sospeso era quindi un falso
                # positivo: il toggle del WiFi non può svegliare un device assente.
                if is_hard_unreachable and pending_silence_alert is not None:
                    print(
                        "alert wifi_frozen in sospeso scartato: powerstation non "
                        "raggiungibile (spenta o staccata, non un freeze)",
                        flush=True,
                    )
                    pending_silence_alert = None
                if is_sensor_silence:
                    # BUGFIX 0.3.52:
                    # prima lo streak veniva incrementato SOLO se la sessione aveva già
                    # ricevuto sensori. Quando invece il reconnect creava sessioni mute,
                    # "wifi_frozen" non partiva mai. Ora contiamo entrambe le condizioni.
                    if sensor_silence_since is None:
                        sensor_silence_since = now
                        _prev_freeze_start = getattr(args, "_last_freeze_start", None)
                        _gap_txt = (
                            f", {now - _prev_freeze_start:.0f}s dal freeze precedente"
                            if _prev_freeze_start else ""
                        )
                        print(
                            f"FREEZE START {time.strftime('%H:%M:%S', time.localtime(now))}"
                            f" (uptime_candidate={getattr(args, '_last_uptime_seen', '?')}{_gap_txt})",
                            flush=True,
                        )
                        args._last_freeze_start = now
                    sensor_silence_streak += 1
                    if not session_had_sensor_data:
                        print(
                            f"LAN sessione muta: nessun sensore ricevuto prima del reconnect "
                            f"(freeze streak={sensor_silence_streak})",
                            flush=True,
                        )
                    else:
                        print(
                            f"WiFi reporting freeze? streak={sensor_silence_streak} "
                            "(sessione aveva dati, poi congelata)",
                            flush=True,
                        )
                    if sensor_silence_streak >= WIFI_FROZEN_ALERT_AFTER:
                        about_to_stop = sensor_silence_streak >= WIFI_FROZEN_STOP_AFTER
                        alert_elapsed = now - last_wifi_frozen_alert
                        if last_wifi_frozen_alert and alert_elapsed < WIFI_FROZEN_ALERT_COOLDOWN \
                                and not about_to_stop:
                            print(
                                f"MQTT wifi_frozen alert soppresso "
                                f"(cooldown {WIFI_FROZEN_ALERT_COOLDOWN - alert_elapsed:.0f}s)",
                                flush=True,
                            )
                        else:
                            # 0.10.2: NON si pubblica qui. "no frames per 30s" vuol dire
                            # ZERO byte ricevuti, e in questo istante un freeze vero e una
                            # powerstation spenta sono identici. Il deep sleep vero invece
                            # continua a mandare i frame minimi (~4 kb) ed e' gestito dal
                            # watchdog telemetria RICCA, che qui non c'entra. L'alert resta
                            # in sospeso: lo pubblica il prossimo connect riuscito (device
                            # raggiungibile = freeze confermato), lo scarta il primo
                            # hard-unreachable (device assente).
                            if rich_alert_streak >= RICH_ALERT_MAX_ATTEMPTS:
                                _dprint(
                                    f"freeze sospetto (streak={sensor_silence_streak}) ma "
                                    f"tentativi esauriti {rich_alert_streak}/"
                                    f"{RICH_ALERT_MAX_ATTEMPTS}: nessun alert, continuo "
                                    "solo a riprovare in LAN",
                                    flush=True,
                                )
                            else:
                                pending_silence_alert = {
                                    "streak": sensor_silence_streak,
                                    "duration": now - sensor_silence_since,
                                    "at": now,
                                }
                                print(
                                    f"freeze sospetto (streak={sensor_silence_streak}): alert "
                                    "wifi_frozen in attesa di conferma dal prossimo connect",
                                    flush=True,
                                )
                    # AUTO-SPEGNIMENTO RIMOSSO (era: stop_addon_after_freeze).
                    # Il SmartSocketWorker delle prese è un thread daemon nello
                    # STESSO processo del bridge: far uscire il processo per un
                    # freeze della powerstation spegneva anche le prese cloud, che
                    # sono del tutto indipendenti dalla LAN (vedi commenti a
                    # _socket_liveness_topic / _publish_smart_socket_discovery).
                    # Le prese devono restare vive. Il bridge continua a
                    # riconnettersi (recupera sempre da solo in ~40s); se il
                    # silenzio sensori persiste oltre SENSOR_SILENCE_RESTART (180s)
                    # parte comunque _restart_process (os.execv in-place) che
                    # preserva lo stato 'online' delle prese. Nessun SystemExit qui.
                    if sensor_silence_streak >= WIFI_FROZEN_STOP_AFTER:
                        _dprint(
                            f"Freeze streak={sensor_silence_streak}: auto-shutdown "
                            "disabilitato (prese cloud indipendenti dal freeze LAN) — "
                            "continuo a riconnettere",
                            flush=True,
                        )

                    if now - sensor_silence_since >= SENSOR_SILENCE_RESTART:
                        print(
                            f"Sensori assenti da {now - sensor_silence_since:.0f}s — availability offline e riavvio bridge",
                            flush=True,
                        )
                        try:
                            mqtt.publish_resilient(availability_topic, "offline", retain=True)
                            availability_offline_sent = True
                        except Exception as exc:
                            print(f"MQTT availability offline publish failed: {exc}", flush=True)
                        try:
                            mqtt.disconnect()
                        except Exception:
                            pass
                        _restart_process(args)
                else:
                    # Un 'host unreachable' / 'timed out' / RST subito dopo un alert
                    # wifi_frozen è l'effetto ATTESO dell'automazione HA che ha appena
                    # spento il WiFi 2.4G del router per il recovery. Se in quel momento
                    # azzeriamo lo streak, l'episodio di freeze non raggiunge mai
                    # WIFI_FROZEN_STOP_AFTER: wifi_frozen viene ripubblicato ad OGNI ciclo
                    # (~60-90s) all'infinito e l'automazione thrasha la WiFi di casa
                    # (migliaia di toggle). Durante un episodio di freeze attivo NON
                    # resettiamo su unreachable/reset: lo streak/episodio si azzera solo
                    # quando tornano dati sensori reali (ramo di ricezione sopra).
                    _in_freeze_episode = sensor_silence_since is not None
                    _recovery_disconnect = is_hard_unreachable or is_lan_reset
                    if _in_freeze_episode and _recovery_disconnect:
                        _dprint(
                            f"disconnessione attesa durante recovery freeze "
                            f"(streak={sensor_silence_streak}) — episodio mantenuto, nessun reset",
                            flush=True,
                        )
                    else:
                        if sensor_silence_streak > 0:
                            print(f"WiFi freeze streak reset (era {sensor_silence_streak})", flush=True)
                        sensor_silence_streak = 0
                        sensor_silence_since = None

                if "mqtt disconnected" in exc_text:
                    print("MQTT disconnected - restarting bridge", flush=True)
                    _restart_process(args)

                if is_lan_reset:
                    print("LAN RST ricevuto dalla powerstation; socket chiuso e riconnessione in corso", flush=True)

                # Detect hard unreachability (WiFi/network down, not just device)
                if is_hard_unreachable:
                    if unreachable_since is None:
                        unreachable_since = now
                        _prev_unreachable_start = getattr(args, "_last_unreachable_start", None)
                        _gap_txt = (
                            f", {now - _prev_unreachable_start:.0f}s dall'unreachable precedente"
                            if _prev_unreachable_start else ""
                        )
                        print(
                            f"UNREACHABLE START {time.strftime('%H:%M:%S', time.localtime(now))}"
                            f" (uptime_candidate={getattr(args, '_last_uptime_seen', '?')}{_gap_txt})",
                            flush=True,
                        )
                        args._last_unreachable_start = now
                else:
                    unreachable_since = None

                # Detect broken-pipe loop (device accepts TCP but drops immediately after login)
                is_broken_pipe = (
                    exc_errno == errno.EPIPE or "broken pipe" in exc_text
                )
                if is_broken_pipe:
                    if broken_pipe_since is None:
                        broken_pipe_since = now
                elif not is_sensor_silence:
                    # Bug 1 fix: non azzerare broken_pipe_since su sensor-silence
                    # (wifi-frozen). Se il device alterna broken-pipe → wifi-frozen
                    # senza mai dare dati, il timer deve restare attivo.
                    # Viene resettato solo quando arrivano dati reali (vedi sopra).
                    broken_pipe_since = None

                print(f"LAN error: {exc}; reconnecting in {reconnect_delay:.0f}s", flush=True)

                if unreachable_since is not None:
                    unreachable_elapsed = now - unreachable_since
                    if unreachable_elapsed >= UNREACHABLE_WIFI_FROZEN_ALERT:
                        # 0.9.37: il watchdog della telemetria ricca vive nella
                        # sessione connessa e da qui non può girare — prima i
                        # tentativi 2/3 e 3/3 non partivano MAI da unreachable.
                        # L'escalation continua quindi anche qui, con gli stessi
                        # limiti (max attempts + cooldown). Il broker MQTT è
                        # locale e resta raggiungibile anche con il device morto.
                        # ...ma SOLO per PROSEGUIRE un episodio gia' aperto dal
                        # watchdog telemetria ricca (streak >= 1). Quello e' l'unico
                        # punto che vede la condizione di deep sleep vera: frame
                        # minimi (~4 kb) che continuano ad arrivare mentre la
                        # telemetria ricca e' ferma. Da qui NON si apre mai un
                        # episodio: 'host unreachable' significa che non arriva
                        # NULLA, cioe' powerstation spenta o staccata, e ciclare il
                        # WiFi del router non puo' svegliare un device assente.
                        _freeze_episode_plausible = rich_alert_streak > 0
                        if (_freeze_episode_plausible
                                and rich_alert_streak < RICH_ALERT_MAX_ATTEMPTS
                                and (last_rich_alert == 0
                                     or now - last_rich_alert >= RICH_ALERT_COOLDOWN)):
                            try:
                                publish_wifi_frozen_alert(
                                    mqtt, args.topic,
                                    reason="lan_unreachable",
                                    streak=rich_alert_streak + 1,
                                    duration=unreachable_elapsed,
                                )
                                rich_alert_streak += 1
                                last_rich_alert = now
                                _save_recovery_state(rich_alert_streak, last_rich_alert)
                                print(
                                    f"LAN unreachable da {unreachable_elapsed:.0f}s → "
                                    f"wifi_frozen pubblicato, tentativo "
                                    f"{rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS} "
                                    "(toggle WiFi router)",
                                    flush=True,
                                )
                                if rich_alert_streak >= RICH_ALERT_MAX_ATTEMPTS:
                                    print(
                                        f"LAN ancora irraggiungibile dopo "
                                        f"{RICH_ALERT_MAX_ATTEMPTS} tentativi WiFi: "
                                        "RINUNCIO ai toggle (niente più cicli del "
                                        "router). Continuo solo a riconnettere; il "
                                        "conteggio si azzera al ritorno di un frame "
                                        "ricco.",
                                        flush=True,
                                    )
                            except Exception as _uexc:
                                print(f"MQTT wifi_frozen (unreachable) publish failed: {_uexc}", flush=True)
                        elif not _freeze_episode_plausible:
                            _dprint(
                                f"LAN unreachable da {unreachable_elapsed:.0f}s: "
                                "non arriva nulla e nessun episodio di freeze aperto "
                                "→ powerstation spenta, nessun toggle WiFi",
                                flush=True,
                            )
                        else:
                            _dprint(
                                f"LAN unreachable da {unreachable_elapsed:.0f}s: "
                                "riconnessione in corso senza nuovo wifi_frozen "
                                f"(tentativi {rich_alert_streak}/{RICH_ALERT_MAX_ATTEMPTS})",
                                flush=True,
                            )

                # Restart the process if the network has been hard-unreachable too long
                # (handles the case where the WiFi router takes >3 min to come back)
                if unreachable_since is not None and now - unreachable_since >= UNREACHABLE_RESTART:
                    # 0.10.1/0.10.2: il restart serve SOLO a tenere in vita
                    # un'escalation gia' in volo — dopo un toggle la LAN diventa
                    # irraggiungibile e il processo va riavviato per arrivare ai
                    # tentativi 2/3 e 3/3 (fix 0.9.37). Fuori da quel caso il
                    # riavvio e' puro spreco: rifa' login cloud + TSL discovery +
                    # ~220 entità ogni 3 minuti, azzera il poll delle prese, e
                    # salta il finally che pubblica 'offline' lasciando la
                    # powerstation 'online' con valori vecchi.
                    _escalation_in_flight = (
                        0 < rich_alert_streak < RICH_ALERT_MAX_ATTEMPTS
                    )
                    if not _escalation_in_flight:
                        if not giveup_mode:
                            giveup_mode = True
                            try:
                                mqtt.publish_resilient(availability_topic, "offline", retain=True)
                                availability_offline_sent = True
                            except Exception as _gexc:
                                print(f"MQTT availability offline publish failed: {_gexc}", flush=True)
                            print(
                                f"PowerStation irraggiungibile da {now - unreachable_since:.0f}s "
                                "e niente altro da tentare → RINUNCIA: availability=offline "
                                "(sensori unavailable), nessun riavvio del bridge, retry ogni "
                                f"{UNREACHABLE_GIVEUP_RECONNECT_DELAY:.0f}s. Le prese restano "
                                "attive; alla riaccensione il bridge torna su da solo.",
                                flush=True,
                            )
                        reconnect_delay = UNREACHABLE_GIVEUP_RECONNECT_DELAY
                    else:
                        print(f"LAN unreachable for {now - unreachable_since:.0f}s — restarting bridge", flush=True)
                        try:
                            mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                        except Exception:
                            pass
                        _restart_process(args)

                # Restart the process if stuck in a broken-pipe loop
                # (device firmware accepts TCP but drops connection after login;
                #  a fresh process start breaks the cycle, same as manual restart)
                if broken_pipe_since is not None and now - broken_pipe_since >= BROKEN_PIPE_RESTART:
                    print(f"Broken-pipe loop for {now - broken_pipe_since:.0f}s — restarting bridge", flush=True)
                    try:
                        mqtt.disconnect()   # DISCONNECT pulito: il broker NON manda LWT "offline"
                    except Exception:
                        pass
                    _restart_process(args)

                # Refresh LAN key on auth failure (unbind/rebind dall'app).
                # Normal runtime is LAN-only; this cloud call is only to recover
                # a changed LAN key/TSL and then continue with LAN frames.
                if "login failed" in exc_text:
                    print("Login failed — refreshing LAN key/TSL from cloud", flush=True)
                    _refresh_lan_key(args)

                if lan_disconnected_since is None:
                    lan_disconnected_since = now

                # Hold MQTT "online" for short WiFi restarts; go offline only after AVAILABILITY_HOLD.
                # Broken-pipe = device accetta TCP ma chiude subito (boot state) → raggiungibile.
                # Sensor-silence = WiFi freeze, TCP vivo → raggiungibile.
                # In entrambi i casi il bridge auto-si-riavvia e torna online: NON andare offline.
                # Offline solo su hard-unreachable (rete giù) o su altri errori prolungati.
                elapsed = now - lan_disconnected_since
                if not availability_offline_sent and elapsed >= AVAILABILITY_HOLD \
                        and not is_broken_pipe and not is_sensor_silence and not is_lan_reset:
                    try:
                        mqtt.publish_resilient(availability_topic, "offline", retain=True)
                        availability_offline_sent = True
                        print(f"MQTT availability → offline after {elapsed:.0f}s outage", flush=True)
                    except Exception as exc:
                        print(f"MQTT availability offline publish failed: {exc}", flush=True)

                # Wait, checking offline trigger every second during the delay
                sleep_until = time.time() + reconnect_delay
                while time.time() < sleep_until:
                    if not availability_offline_sent and lan_disconnected_since is not None \
                            and not is_broken_pipe and not is_sensor_silence and not is_lan_reset:
                        if time.time() - lan_disconnected_since >= AVAILABILITY_HOLD:
                            try:
                                mqtt.publish_resilient(availability_topic, "offline", retain=True)
                                availability_offline_sent = True
                            except Exception as exc:
                                print(f"MQTT availability offline publish failed: {exc}", flush=True)
                    # Keepalive MQTT durante l'attesa: il CONNECT dichiara
                    # keepalive=60s e il broker stacca a 1.5x (90s) se non riceve
                    # nulla. Il ping della sessione connessa qui non gira, e in
                    # giveup mode ogni giro dura UNREACHABLE_GIVEUP_RECONNECT_DELAY:
                    # senza questo la connessione powerstation morirebbe ogni volta.
                    # Fallimento NON fatale: siamo dentro l'except, un'eccezione
                    # qui uscirebbe dal loop e spegnerebbe anche il worker prese.
                    _ping_now = time.time()
                    if _ping_now - last_retry_ping >= MQTT_PING_INTERVAL:
                        last_retry_ping = _ping_now
                        try:
                            mqtt.ping()
                        except Exception as _pexc:
                            _dprint(f"MQTT keepalive ping fallito durante i retry: {_pexc}", flush=True)
                            try:
                                mqtt.reconnect()
                            except Exception:
                                pass
                    time.sleep(min(1.0, max(0.0, sleep_until - time.time())))

                if giveup_mode:
                    # Rinuncia: retry lenti finché la powerstation non torna.
                    reconnect_delay = UNREACHABLE_GIVEUP_RECONNECT_DELAY
                else:
                    reconnect_delay = min(reconnect_delay * 1.5, RECONNECT_DELAY_MAX)

    finally:
        try:
            mqtt.publish(availability_topic, "offline", retain=True)
        except Exception as exc:
            print(f"MQTT availability offline publish failed on exit: {exc}", flush=True)
        try:
            mqtt.disconnect()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Landbook/Wonderfree generic LAN -> HA MQTT bridge")
    parser.add_argument("--device-host", default="")
    parser.add_argument("--device-port", type=int, default=6607)
    parser.add_argument("--key", required=True, help="LAN key (base64). Retrieved by addon_run.py from the cloud or local cache.")
    parser.add_argument("--mqtt-host", default="core-mosquitto")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-user")
    parser.add_argument("--mqtt-password")
    parser.add_argument("--device-key", default=os.environ.get("DEVICE_KEY", DEVICE_KEY))
    parser.add_argument("--topic", default=f"landbook/{DEVICE_KEY}")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--report-interval", type=int, default=10)
    parser.add_argument("--battery-capacity-wh", type=float, default=2048)
    parser.add_argument("--battery-cache-path", default="/data/landbook_battery_cache.json")
    parser.add_argument("--battery-current-fallback-voltage", type=float, default=52.8)
    parser.add_argument("--grid-frequency-default", type=float, default=50)
    parser.add_argument("--ac-zero-hold-seconds", type=float, default=18)
    parser.add_argument("--show-firmware-sensors", action="store_true", default=False)
    parser.add_argument("--smart-sockets-enabled", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--smart-socket-poll-interval", type=int, default=30)
    parser.add_argument("--smart-socket-1-device-key", default="")
    parser.add_argument("--smart-socket-1-product-key", default="")
    parser.add_argument("--smart-socket-1-name", default="")
    parser.add_argument("--smart-socket-2-device-key", default="")
    parser.add_argument("--smart-socket-2-product-key", default="")
    parser.add_argument("--smart-socket-2-name", default="")
    parser.add_argument("--output-power-min", type=int, default=100)
    parser.add_argument("--output-power-max", type=int, default=800)
    parser.add_argument("--output-power-step", type=int, default=10)
    parser.add_argument("--output-power-debounce", type=float, default=0.25)
    parser.add_argument("--device-tx-min-interval", type=float, default=0.6)
    parser.add_argument("--command-duplicate-window", type=float, default=COMMAND_DUPLICATE_WINDOW)
    parser.add_argument("--command-opposite-window", type=float, default=COMMAND_OPPOSITE_WINDOW)
    parser.add_argument("--mqtt-stale-drain-seconds", type=float, default=2.0)
    parser.add_argument(
        "--freeze-detection-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Se False, disabilita la riconnessione automatica per 'silenzio sensori' "
             "(SENSOR_RECONNECT_AFTER) — utile per testare se il ciclo naturale Low/LAN+WiFi "
             "del device viene scambiato per un freeze reale. Non tocca il controllo 'no frames' "
             "(LAN davvero morta), che resta sempre attivo. Default True = comportamento invariato.",
    )
    parser.add_argument(
        "--clear-command-states-on-start",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Se True (default) all'avvio azzera gli stati retained di select e number: "
             "le entita' restano 'unknown' finche' non e' la LAN a riportare il valore "
             "reale. Evita di mostrare un valore vecchio (retained della sessione "
             "precedente) che puo' essere cambiato mentre il bridge era fermo. Se False, "
             "conserva l'ultimo valore visto sulla LAN. In nessun caso vengono usati i "
             "valori del cloud.",
    )
    args = parser.parse_args()
    print(f"Landbook LAN MQTT Bridge {APP_VERSION} starting", flush=True)
    run(args)


if __name__ == "__main__":
    main()
