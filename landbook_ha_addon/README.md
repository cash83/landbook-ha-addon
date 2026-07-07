# Landbook LAN MQTT Bridge

## Versione 0.9.18 - Availability prese separata

Bridge Home Assistant per Landbook/Wonderfree:

- usa il cloud solo all'avvio per ottenere o aggiornare LAN key e TSL;
- salva LAN key e TSL in cache locale;
- lavora in LAN verso la powerstation e pubblica su MQTT;
- integra le prese smart Wonderfree associate, con lettura cloud e switch ON/OFF
  tramite MQTT cloud Wonderfree;
- invia subscription, `bus_mask` business e `bus_refresh` ogni circa 10 secondi;
- manda una sola volta `high_frequency_reporting=3` dopo il login LAN.

## Novita' 0.9.7

- La `bus_mask` resta generata dal TSL locale, ma esclude `device_type`/ID `7`
  e `measure_data`/ID `18`. Sul firmware FPPT-T2400 osservato, la mask completa
  con questi due ID riceveva solo ACK/heartbeat; la mask business senza `7` e
  `18` faceva arrivare i frame telemetria cifrati `cmd=20`.
- Aggiunto evento MQTT `lan_reset` quando la powerstation chiude il socket TCP
  con RST. Il bridge lo distingue da `lan_unreachable`, si riconnette e non
  marca subito la disponibilita' come offline.
- Decoder batteria aggiornato per il blocco LAN reale `battery_data`/`0x001c`.
  Dal frame batteria vengono letti SOC, tempo residuo, tensione, potenza e
  temperatura.
- Walker TTLV aggiornato per il prefisso compatto `0x09`, usato dal firmware
  per alcuni valori interi a 2 byte.

## Novita' 0.9.8

- Se l'account Wonderfree contiene anche prese smart, la discovery automatica
  preferisce la powerstation (`p11tpn`/`p11uve`) invece di usare semplicemente
  il primo dispositivo restituito dal cloud.
- Se `device_key` e' configurato manualmente, quello resta prioritario.

## Novita' 0.9.9

- Discovery delle smart socket Wonderfree (`p11sPk`) presenti nello stesso
  account e pubblicazione in Home Assistant di switch ON/OFF, potenza, tensione,
  corrente, potenza apparente, fattore di potenza, energia e potenza totale.
- Nuovo controllo `Intelligent Charging Power` in Home Assistant: permette di
  impostare 200/400/600/800 W senza esporre giorni o orari. Il bridge mantiene
  internamente un piano sempre valido e cambia solo la potenza.
- Le smart socket usano cloud Wonderfree per lettura e comando ON/OFF; il
  runtime LAN della powerstation resta invariato.

## Novita' 0.9.10

- Aggiunto fallback manuale per pubblicare le due prese anche quando la cache
  discovery non contiene `smart_socket_devices`.
- Config precompilato con `00D6CBEDD001` e `00D6CBEDCFA7`.

## Novita' 0.9.11

- Le entita' delle prese vengono pubblicate sotto lo stesso dispositivo Home
  Assistant `Landbook LAN Device`, invece di creare dispositivi separati.

## Novita' 0.9.12

- `smart_socket_poll_interval` riguarda solo le prese smart cloud, non la
  powerstation LAN.
- Versione intermedia con default 70 secondi e limite minimo 63 secondi per
  prudenza cloud; superata dalla 0.9.13 dopo confronto sul comportamento delle
  prese Wonderfree.

## Novita' 0.9.13

- Default prese riportato a 20 secondi per aggiornamenti piu' rapidi.
- Il limite minimo runtime e' 10 secondi e vale solo per le prese cloud.

## Novita' 0.9.14

- Le due prese note vengono pubblicate anche se Home Assistant mantiene un
  vecchio `/data/options.json` senza i nuovi campi `smart_socket_*`.
- Nei log appare `Smart socket discovery published: 2` quando le entita' prese
  vengono inviate al broker MQTT.

## Novita' 0.9.15

- Le prese vengono pubblicate come dispositivi Home Assistant separati dalla
  powerstation, con `via_device` verso `Landbook LAN Device`.

## Novita' 0.9.16

- Anche i sensori delle prese vengono ricreati con `unique_id` separati, cosi'
  Home Assistant non li lascia agganciati alla powerstation per via del registro
  entita' gia' esistente.
- Le discovery retained vecchie dei sensori/switch presa vengono svuotate prima
  di pubblicare le nuove.

## Novita' 0.9.17

- I sensori delle prese usano `force_update: true`, quindi Home Assistant
  registra ogni poll anche quando il valore resta uguale.

## Novita' 0.9.18

- Ogni presa usa un topic availability separato dalla powerstation.
- Il poll prese legge `onlineStatus` da `userDeviceList`: se una presa viene
  staccata e il cloud la marca offline, switch e sensori della presa diventano
  non disponibili in Home Assistant.

## Cache

- `/data/landbook_lan_key.json`: LAN key associata ad account e piattaforma.
- `/data/landbook_tsl.json`: TSL usato dal runtime.
- `/data/discovered.json`: cache discovery cloud, inclusi eventuali dispositivi
  smart socket associati.
- `/share/landbook_tsl.json`: copia leggibile del TSL per controllo manuale.

## Configurazione

- `wf_email` e `wf_password`: credenziali app Landbook/Wonderfree.
- `app`: piattaforma cloud (`landbook`, `wonderfree`, `landecia`,
  `northamerica`, `europe`, `china`).
- `device_host`: IP della powerstation in LAN.
- `device_port`: porta LAN, default `6607`.
- `mqtt_host`, `mqtt_port`, `mqtt_user`, `mqtt_password`: broker MQTT.
- `battery_capacity_wh`: capacita' nominale batteria per sensori derivati.
- `smart_sockets_enabled`: abilita la pubblicazione delle prese smart associate.
- `smart_socket_poll_interval`: secondi tra una lettura cloud e l'altra delle
  prese smart. Default 20; valori sotto 10 vengono alzati automaticamente a 10.
- `smart_socket_1_*` e `smart_socket_2_*`: fallback manuale device key,
  product key e nome delle prese.
- `freeze_detection_enabled`: se `false`, disabilita la riconnessione automatica
  per silenzio sensori. Il controllo "no frames" resta sempre attivo.
- `log_level`: `debug`, `info`, `warning`, `error`.

## Runtime LAN

Comportamento previsto:

- login LAN rapido;
- subscription iniziale con intervallo sensori di circa 10 secondi;
- rinnovo subscription raro, circa ogni 120 secondi;
- `bus_mask` TSL business ogni circa 10 secondi, con debounce minimo 5s;
- `bus_refresh` ogni circa 10 secondi, con debounce minimo 5s;
- invio singolo `high_frequency_reporting=3` subito dopo ogni login;
- riconnessione se non arrivano frame entro 30s o sensori entro 50s;
- comandi Home Assistant inviati via LAN usando il TSL.

## Evento WiFi Frozen

Il bridge pubblica eventi non retained su:

```text
landbook/<device_key>/event/wifi_frozen
```

Payload esempio:

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

- `sensor_silence`: il TCP puo' essere vivo, ma i sensori non arrivano piu';
- `lan_unreachable`: la powerstation non e' raggiungibile in LAN per circa 30s;
- `lan_reset`: la powerstation ha chiuso il socket TCP con RST; il bridge si
  riconnette e non lo considera da solo una rete irraggiungibile.

Il bridge mantiene un cooldown interno di circa 50 secondi tra alert ripetuti.

## Verifica 0.9.9

Prima dello zip eseguire:

- `python -m compileall -q .`;
- verifica ZIP: cartella radice `landbook_ha_addon/`, separatori `/`, nessun
  `__pycache__` o `.pyc`, `config.yaml` versione `0.9.9`.
