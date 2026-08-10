# Landbook LAN MQTT Bridge

Bridge Home Assistant per la **powerstation Landbook/Wonderfree** (es. FPPT-T2400)
e per le **prese smart Wonderfree** associate allo stesso account.

Powerstation e prese vivono nello **stesso add-on ma in modo indipendente**:

- **Powerstation** → collegamento **LAN diretto** (protocollo TSL cifrato):
  telemetria e comandi in tempo reale.
- **Prese smart** → **cloud Wonderfree**: lettura stato e comando ON/OFF.

Per la **powerstation**, il cloud serve solo a ottenere o aggiornare LAN key e
TSL quando la cache locale manca o non è più valida; il runtime della
powerstation resta tutto in LAN. Le **prese smart** sono un percorso separato e
continuano a usare il cloud Wonderfree tramite il loro worker indipendente.

## Powerstation (LAN)

- login LAN rapido e subscription telemetria ogni ~10 secondi;
- `bus_mask` business + `bus_refresh` ogni ~10 secondi (debounce minimo 5s);
- invio singolo di `high_frequency_reporting=3` (LAN + Wi-Fi) dopo ogni login;
- riconnessione automatica se non arrivano frame entro ~30s o sensori entro ~50s
  (la rilevazione per silenzio sensori è disattivabile; il controllo "no frames"
  resta sempre attivo);
- comandi da Home Assistant inviati via LAN usando il TSL.

Entità pubblicate: batteria (SOC, tempo residuo, tensione, corrente, potenza,
temperatura, singole celle), uscite AC/DC/USB/Type-C, rete, PV, potenze totali di
ingresso/uscita, stato dispositivo e codice errore; controlli AC/DC out, on-grid,
buzzer, LED, silent charge, working mode, power consumption plan, screen off time,
SOC discharge, on-grid power setting, high frequency reporting e
`Intelligent Charging Power` (200/400/600/800 W).

## Prese smart (cloud) — worker indipendente

Le prese sono gestite da un **worker dedicato con connessione MQTT propria**,
**completamente separato dal loop LAN della powerstation**:

- se la powerstation va **offline o in freeze**, le prese continuano a essere
  lette e comandate; e viceversa, un problema cloud sulle prese non tocca la
  powerstation;
- attraverso un riavvio del bridge le prese restano "online" (Last Will dedicato).

Comportamento:

- rilevate automaticamente dall'account (product key `p11sPk`); se il cloud non
  ha ancora popolato la cache, fallback sulle device key indicate in configurazione;
- ogni presa è un **dispositivo separato ma agganciato alla powerstation**
  (`via_device` → `Landbook LAN Device`): in Home Assistant le prese appaiono
  raggruppate sotto la powerstation, pur restando device a sé;
- entità per presa: switch ON/OFF, potenza, tensione, corrente, potenza apparente,
  fattore di potenza, energia; più un sensore `Smart socket total power`;
- disponibilità doppia (bridge vivo **e** presa online sul cloud): se una presa
  viene staccata, il cloud la marca offline e le sue entità diventano non
  disponibili in Home Assistant;
- comando ON/OFF inviato via MQTT cloud Wonderfree;
- polling ogni `smart_socket_poll_interval` secondi (default 30, minimo 10),
  indipendente dal runtime LAN.

## Configurazione

- `wf_email`, `wf_password`: credenziali app Landbook/Wonderfree.
- `app`: piattaforma cloud (`wonderfree`, `landbook`, `landecia`, `northamerica`,
  `europe`, `china`).
- `device_host`: IP della powerstation in LAN.
- `device_port`: porta LAN, default `6607`.
- `mqtt_host`, `mqtt_port`, `mqtt_user`, `mqtt_password`: broker MQTT.
- `battery_capacity_wh`: capacità nominale batteria per i sensori derivati.
- `smart_sockets_enabled`: abilita la pubblicazione delle prese smart associate.
- `smart_socket_poll_interval`: secondi tra una lettura cloud e l'altra delle
  prese (default 30; valori sotto 10 vengono alzati automaticamente a 10).
- `smart_socket_1_*` e `smart_socket_2_*`: fallback manuale (device key, product
  key, nome) usato solo se il cloud non popola la lista prese.
- `freeze_detection_enabled`: se `false`, disabilita la riconnessione automatica
  per silenzio sensori (il controllo "no frames" resta sempre attivo).
- `clear_command_states_on_start`: se `true` (default) all'avvio azzera gli stati
  retained di select e number. Le entità restano `unknown` finché non è la LAN a
  riportare il valore reale, così non viene mai mostrato un valore vecchio che
  potrebbe essere cambiato mentre il bridge era fermo (dal pannello o dall'app).
  Se `false`, conserva l'ultimo valore letto sulla LAN. In nessuno dei due casi
  vengono usati i valori del cloud. Alcuni codici scendono dalla LAN di rado, per
  cui con l'opzione attiva possono restare vuoti per un po' dopo un riavvio.
- `log_level`: `debug`, `info`, `warning`, `error`.

## Cache

- `/data/landbook_lan_key.json`: LAN key associata ad account e piattaforma.
- `/data/landbook_tsl.json`: TSL usato dal runtime.
- `/data/discovered.json`: cache discovery cloud, incluse le prese smart associate.
- `/share/landbook/`: copia leggibile del TSL (summary + raw) per controllo manuale.

## Evento `wifi_frozen`

Il bridge pubblica eventi non retained su:

```text
landbook/<device_key>/event/wifi_frozen
```

Payload di esempio:

```json
{
  "reason": "lan_reset",
  "ts": 1782690000,
  "message": "PowerStation ha chiuso la connessione LAN con TCP RST. Il bridge si riconnette.",
  "streak": 1,
  "duration": 0
}
```

Valori principali di `reason`:

- `sensor_silence`: il TCP può essere vivo ma i sensori non arrivano più;
- `lan_unreachable`: la powerstation non è raggiungibile in LAN per ~30s;
- `lan_reset`: la powerstation ha chiuso il socket TCP con RST; il bridge si
  riconnette e non lo considera da solo rete irraggiungibile.

Il bridge mantiene un cooldown interno di ~50 secondi tra alert ripetuti.

## Requisiti

- broker MQTT (add-on Mosquitto o esterno);
- `paho-mqtt` (già incluso nell'immagine dell'add-on) per il worker prese e il
  comando cloud.
