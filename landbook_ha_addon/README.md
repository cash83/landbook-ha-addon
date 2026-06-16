# Landbook LAN MQTT Bridge

Home Assistant add-on per power station Landbook / Wonderfree / Landecia.
Scopre automaticamente switch, select, number e sensori usando lo schema TSL del
dispositivo recuperato dal cloud. Le entita' Home Assistant vengono create dai
codici reali del TSL, senza una lista statica FPPT-T2400 nel bridge. Dopo il
recupero iniziale, il funzionamento normale avviene in LAN tramite l'IP locale
della power station e MQTT discovery.

## Progetto non ufficiale

Questo add-on e' un progetto open-source della community e non e' affiliato,
approvato o sponsorizzato da Wonderfree, Landbook, Landecia, Pecron o dai
rispettivi produttori. I marchi appartengono ai rispettivi proprietari.

L'uso del bridge avviene sotto la propria responsabilita'. Per supporto
ufficiale del dispositivo, firmware, app o account, fai riferimento ai canali
ufficiali del produttore.

## Account ufficiale richiesto

Per usare il bridge serve avere gia':

- un account attivo nell'app ufficiale del dispositivo
- il dispositivo gia' registrato nell'app ufficiale

L'add-on usa quelle credenziali solo per recuperare automaticamente LAN key e
schema TSL. Non crea account separati e non aggira la registrazione ufficiale.

La versione corrente e' quella mostrata nel pannello dell'add-on, nel campo
`Versione attuale`.

## Come funziona

L'add-on usa il cloud Landbook/Wonderfree solo in fase di avvio o recupero:
scarica la LAN key e lo schema TSL del dispositivo, poi li salva in cache locale.

Dopo l'avvio, il flusso normale e':

```text
Power station LAN/Wi-Fi locale -> add-on -> MQTT -> Home Assistant
```

Quindi sensori e comandi passano tramite connessione locale verso l'indirizzo IP
della power station. Home Assistant riceve entita' e stati tramite MQTT discovery.
Gli stati degli switch non vengono letti dal cloud: seguono i report LAN e i
comandi inviati da Home Assistant.

## Installazione locale

1. Copia la cartella dell'add-on nella share degli add-on locali di Home Assistant.
2. In Home Assistant vai in **Impostazioni -> Add-on -> Add-on Store**.
3. Apri il menu in alto a destra e premi **Reload**.
4. Installa **Landbook LAN MQTT Bridge**.
5. Compila le opzioni dell'add-on e avvialo.

## Opzioni principali

- `wf_email` e `wf_password`: credenziali dell'app Landbook/Wonderfree. Servono per recuperare la LAN key.
- `app`: piattaforma cloud da usare, ad esempio `landbook`, `wonderfree` o `europe`.
- `device_key`: opzionale. Se vuoto, viene scelto automaticamente dal cloud quando possibile.
- `device_host`: indirizzo IP locale della power station.
- `device_port`: porta LAN del dispositivo, normalmente `6607`.
- `mqtt_host`: broker MQTT, normalmente `core-mosquitto`.
- `mqtt_port`: porta MQTT, normalmente `1883`.
- `mqtt_user` e `mqtt_password`: credenziali MQTT, se il broker le richiede.
- `battery_capacity_wh`: capacita' nominale della batteria in Wh.
- `use_ttlv_walker`: pubblicazione shadow/debug dei valori TSL decodificati.

## Nota su use_ttlv_walker

Lascia normalmente:

```yaml
use_ttlv_walker: false
```

Il decode TSL viene usato internamente per alimentare le entita'. L'opzione
`use_ttlv_walker: true` pubblica anche una copia shadow dei valori su topic di
debug, utile solo per confronto o reverse engineering.

## MQTT

Se il broker MQTT richiede autenticazione, compila sia `mqtt_user` sia
`mqtt_password`.

Esempio:

```yaml
mqtt_host: core-mosquitto
mqtt_port: 1883
mqtt_user: mqtt
mqtt_password: tua_password
```

Se il broker MQTT non richiede autenticazione, lascia vuoti entrambi:

```yaml
mqtt_user: ""
mqtt_password: ""
```

Evita di impostare solo `mqtt_password` lasciando `mqtt_user` vuoto, perche'
alcuni broker MQTT rifiutano una connessione con password ma senza username.

## Note su LAN e riconnessioni

La parola LAN indica una connessione locale verso l'IP della power station. Se la
power station e' collegata in Wi-Fi, la stabilita' dipende comunque dal modulo
Wi-Fi del dispositivo e dalla rete wireless.

Il bridge riconnette automaticamente quando non riceve sensori per un certo
periodo. Nei log questo puo' apparire come:

```text
no sensor data for 30s -- reconnecting
WiFi reporting freeze?
```

In questo caso MQTT puo' essere ancora funzionante: il problema e' spesso il
reporting LAN/Wi-Fi della power station che si e' congelato.

Il bridge protegge anche la power station da comandi troppo ravvicinati:
duplicati immediati e rimbalzi ON/OFF o select A/B vengono ignorati per pochi
secondi prima di arrivare alla LAN. Questo evita di stressare il modulo Wi-Fi
del dispositivo quando Home Assistant o la UI inviano piu' comandi in sequenza.

## Automazione wifi_frozen

Quando la power station resta raggiungibile in LAN ma smette di pubblicare
sensori reali, il bridge pubblica un evento MQTT per permettere ad Home
Assistant di eseguire un recovery automatico, ad esempio riavviando il Wi-Fi
del router o una presa smart collegata al router stesso.

Topic evento:

```text
landbook/<device_key>/event/wifi_frozen
```

Esempio reale:

```text
landbook/900371d8a277/event/wifi_frozen
```

### Quando viene pubblicato

- dopo circa 30 secondi senza sensori reali dalla power station
- dopo circa 30 secondi di LAN irraggiungibile

Il bridge distingue i sensori veri dai frame parziali o poco utili. Per esempio
pacchetti come `pv_data: 0` da soli non bastano piu' a tenere "viva" la
connessione: se arrivano solo questi frame e non arrivano piu' valori come
`battery_percentage`, `pv_input_power`, `grid_b_power`, `battery_total_power`
o simili, il bridge considera la telemetria congelata e pubblica `wifi_frozen`.

### Payload evento

L'evento e' in JSON e puo' contenere campi come:

- `reason`: `sensor_silence` oppure `lan_unreachable`
- `streak`: numero di freeze consecutivi rilevati
- `duration`: durata del freeze in secondi
- `ts`: timestamp evento

### A cosa serve l'automazione

L'automazione Home Assistant puo' ascoltare questo topic e fare una o piu'
azioni di recovery, per esempio:

- riavviare il Wi-Fi del router
- spegnere e riaccendere una smart plug del router
- inviare una notifica
- registrare il problema nel logbook

### Nota importante

Se il bridge gira normalmente ma riceve solo frame vuoti o parziali, l'evento
`wifi_frozen` viene comunque pubblicato dopo circa 30 secondi.

Se invece il processo del bridge si blocca completamente e non riesce piu' a
pubblicare nulla, nessun evento MQTT potra' essere emesso fino al riavvio del
bridge stesso.

## Comportamento dei sensori

L'add-on usa MQTT discovery e pubblica `availability`, quindi sensori e controlli
vanno offline quando il bridge non gira.

Alcuni sensori possono risultare `Sconosciuto` quando l'uscita corrispondente e'
spenta o quando il dispositivo non invia quel dato nel report corrente.

## Debug

Per indagare problemi di connessione o decoding, imposta:

```yaml
log_level: debug
```

Non pubblicare log o opzioni contenenti credenziali, token, LAN key o password.
