# Landbook LAN MQTT Bridge

Bridge Home Assistant per la **powerstation Landbook/Wonderfree** (es. FPPT-T2400)
e per le **prese smart Wonderfree** associate allo stesso account.

Powerstation e prese vivono nello **stesso add-on ma in modo indipendente**:

- **Powerstation** → collegamento **LAN diretto** (protocollo TTLV cifrato AES):
  telemetria e comandi in tempo reale.
- **Prese smart** → **cloud Wonderfree**: lettura stato e comando ON/OFF.

Per la **powerstation**, il cloud serve solo a ottenere o aggiornare LAN key e
TSL quando la cache locale manca o non è più valida; il runtime della
powerstation resta tutto in LAN. Le **prese smart** sono un percorso separato e
continuano a usare il cloud Wonderfree tramite il loro worker indipendente.

## Powerstation (LAN)

- scoperta del dispositivo via UDP broadcast sulla porta 6606, con ripiego
  sull'ultimo indirizzo noto e su `device_host` se configurato;
- login LAN con sfida/risposta SHA-256 sulla LAN key, poi heartbeat ogni
  `read_interval` secondi;
- lettura completa di tutti gli id del TSL ogni `read_interval` secondi e
  ri-arming del reporting ad alta frequenza ogni `rearm_interval` secondi;
- riconnessione automatica se non arrivano frame entro `frame_timeout` secondi,
  o se la telemetria utile manca da `freeze_alert_after` secondi (90 di default);
- comandi da Home Assistant inviati via LAN usando gli id del TSL.

Entità pubblicate: batteria (percentuale, energia residua, tempo residuo,
tensione, corrente, potenza, temperatura, 13 tensioni di cella), uscite AC/DC
12V/24V/USB/Type-C, rete, PV, potenze totali di ingresso e uscita, temperature
di BMS, inverter e MPPT, stato dispositivo, codice guasto e stato della
connessione LAN.

Controlli: uscita AC, uscita DC, uscita on-grid, buzzer, LED, silent charge
(6 switch); modalità di lavoro, SOC di scarica, spegnimento schermo, piano
consumi (4 select); potenza on-grid (1 number). L'elenco esatto è letto dal TSL
del dispositivo, quindi segue il modello e il firmware.

## Prese smart (cloud) — worker indipendente

Le prese sono gestite da un **worker dedicato con connessione MQTT propria**,
**completamente separato dal loop LAN della powerstation**:

- se la powerstation va **offline o in freeze**, le prese continuano a essere
  lette e comandate; e viceversa, un problema cloud sulle prese non tocca la
  powerstation;
- attraverso un riavvio del bridge le prese restano "online" (Last Will dedicato).

Comportamento:

- rilevate automaticamente dall'account (product key `p11sPk`); se il cloud non
  ha ancora popolato la cache, ripiego sulle device key indicate in configurazione;
- ogni presa è un **dispositivo separato ma agganciato alla powerstation**
  (`via_device` → `Landbook LAN Device`): in Home Assistant le prese appaiono
  raggruppate sotto la powerstation, pur restando device a sé;
- entità per presa: switch ON/OFF, potenza, tensione, corrente, potenza apparente,
  fattore di potenza, energia; più un sensore `Smart socket total power`;
- disponibilità doppia (bridge vivo **e** presa online sul cloud): staccando una
  presa dalla corrente le sue entità diventano non disponibili. Il ritardo è del
  cloud, che aspetta la scadenza del proprio keepalive prima di dichiararla
  caduta: misurati alcuni minuti, più al massimo un `smart_socket_poll_interval`;
- comando ON/OFF inviato via MQTT cloud Wonderfree;
- una presa che non risponde non interrompe la lettura delle altre.

## Configurazione

- `wf_email`, `wf_password`: credenziali app Landbook/Wonderfree.
- `app`: piattaforma cloud (`wonderfree`, `landbook`, `landecia`, `northamerica`,
  `europe`, `china`).
- `device_key`: device key della powerstation, se ne hai più di una sull'account.
- `device_host`: IP della powerstation in LAN (facoltativo: senza, la cerca via
  UDP broadcast).
- `device_port`: porta LAN, default `6607`.
- `udp_scan_cidr`: sottorete da scandire quando il broadcast non basta
  (es. `192.168.1.0/24`); al massimo 512 indirizzi.
- `mqtt_host`, `mqtt_port`, `mqtt_user`, `mqtt_password`: broker MQTT.
- `topic_prefix`: prefisso dei topic di servizio, default `landbook_test`. Le
  entità di Home Assistant stanno comunque sotto `landbook/<device_key>/`.
- `battery_capacity_wh`: capacità nominale batteria per i sensori derivati.
- `smart_sockets_enabled`: abilita la pubblicazione delle prese smart associate.
- `smart_socket_poll_interval`: secondi tra una lettura cloud e l'altra delle
  prese (default 30; valori sotto 10 vengono alzati automaticamente a 10).
- `smart_socket_1_*` e `smart_socket_2_*`: ripiego manuale (device key, product
  key, nome) usato solo se il cloud non popola la lista prese.
- `read_interval`: secondi tra una lettura completa del TSL e la successiva
  (default 10, minimo 5).
- `rearm_interval`: secondi tra un ri-arming del reporting e il successivo
  (default 20, minimo 10).
- `hfr_mode`: reporting ad alta frequenza — `0` infrequente, `1` LAN (default),
  `2` Wi-Fi, `3` LAN + Wi-Fi.
- `frame_timeout`: secondi di silenzio totale dopo i quali la sessione LAN viene
  ricreata (default 30, minimo 15).
- `freeze_detection_enabled`: se `false`, disabilita l'allarme e la riconnessione
  per telemetria ferma (il controllo "nessun frame" resta sempre attivo).
- `freeze_alert_after`: secondi di telemetria ferma prima dell'allarme
  `wifi_frozen` (default 90).
- `freeze_alert_cooldown`: secondi minimi fra due allarmi (default 50).
- `timezone`: fuso usato per gli orari del log, default `Europe/Rome`.
- `log_level`: `debug`, `info`, `warning`, `error`.

## Cache

- `/data/landbook_lan_key.json`: LAN key associata ad account e piattaforma.
- `/data/landbook_lan_host.json`: ultimo indirizzo LAN visto.
- `/data/landbook_tsl.json`: TSL usato dal runtime.
- `/share/landbook_tsl.json`: copia leggibile dello stesso TSL, per ispezione manuale.

## Evento `wifi_frozen`

Il bridge pubblica eventi non retained su:

```text
landbook/<device_key>/event/wifi_frozen
```

Payload di esempio:

```json
{
  "reason": "sensor_silence",
  "ts": 1782690000,
  "message": "PowerStation WiFi/LAN reporting frozen. Riavviare il WiFi del router o la powerstation.",
  "streak": 1,
  "duration": 95
}
```

L'evento segnala che il dispositivo risponde ancora ma ha smesso di riportare la
telemetria: su questi firmware lo sblocca un riavvio del Wi-Fi del router.
Il bridge mantiene un cooldown tra alert ripetuti, regolabile con
`freeze_alert_cooldown` (default 50 secondi).

## Note sul protocollo, per chi mette le mani nel codice

Tre trappole costate parecchio tempo, tutte verificate sul campo:

- **I report arrivano in frame separati e parziali.** Un frame contiene solo
  alcuni gruppi del TSL, quindi i valori derivati (le potenze totali) vanno
  calcolati sulla cache unita, non sul singolo frame.
- **Il frame di risposta alla lettura completa non valorizza il gruppo
  `ac_data`.** È l'unico che contiene `mac_set`, e lì `ac_power` torna 0 anche
  con 2,4 kW veri alle prese: quegli zeri vanno scartati prima di entrare in
  cache. L'uscita AC buona arriva solo nel report spontaneo di `ac_data`.
- **`ac_power` e `grid_b_power` sono due cose diverse**: il primo è l'uscita
  delle prese AC (gruppo `ac_data`), il secondo è il micro inverter verso casa
  (gruppo `grid_data`). Non devono sovrascriversi.

Inoltre il TSL dichiara `step: 0.1` per `ac_voltage` e `bms_mos_temp`, ma il
dispositivo manda volt e gradi interi: senza correzione si leggono 23 V invece
di 230 V e un decimo della temperatura reale.

## Requisiti

- broker MQTT (add-on Mosquitto o esterno);
- un account attivo nell'app ufficiale, con il dispositivo già registrato.
