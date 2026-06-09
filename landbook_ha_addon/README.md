# Landbook LAN MQTT Bridge

Home Assistant add-on for the Landbook FPPT-T2400 LAN MQTT bridge.

## Versione

Add-on: `0.3.82`

## Come funziona

L'add-on usa il cloud Landbook/Wonderfree solo per recuperare automaticamente la LAN key del dispositivo.

Dopo l'avvio, il flusso normale e':

```text
Power station LAN/Wi-Fi locale -> add-on -> MQTT -> Home Assistant
```

Quindi sensori e comandi passano tramite connessione locale verso l'indirizzo IP della power station, mentre Home Assistant riceve i dati tramite MQTT discovery.

## Installazione locale

1. Copia la cartella `landbook_ha_addon` nella share degli add-on locali di Home Assistant.
2. In Home Assistant vai in **Impostazioni -> Add-on -> Add-on Store**.
3. Apri il menu in alto a destra e premi **Reload**.
4. Installa **Landbook LAN MQTT Bridge**.
5. Compila le opzioni dell'add-on e avvialo.

## Opzioni principali

- `wf_email` e `wf_password`: credenziali dell'app Landbook/Wonderfree. Servono per recuperare la LAN key.
- `app`: piattaforma cloud da usare, ad esempio `landbook`, `wonderfree` o `europe`.
- `device_host`: indirizzo IP locale della power station.
- `device_port`: porta LAN del dispositivo, normalmente `6607`.
- `mqtt_host`: broker MQTT, normalmente `core-mosquitto`.
- `mqtt_port`: porta MQTT, normalmente `1883`.
- `mqtt_user` e `mqtt_password`: credenziali MQTT, se il broker le richiede.
- `battery_capacity_wh`: capacita' nominale della batteria in Wh.

## MQTT

Se il broker MQTT richiede autenticazione, compila sia `mqtt_user` sia `mqtt_password`.

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

Evita di impostare solo `mqtt_password` lasciando `mqtt_user` vuoto, perche' alcuni broker MQTT rifiutano una connessione con password ma senza username.

## Note su LAN e riconnessioni

La parola LAN indica una connessione locale verso l'IP della power station. Se la power station e' collegata in Wi-Fi, la stabilita' dipende comunque dal modulo Wi-Fi del dispositivo e dalla rete wireless.

Il bridge riconnette automaticamente quando non riceve sensori per un certo periodo. Nei log questo puo' apparire come:

```text
no sensor data for 40s -- reconnecting
WiFi reporting freeze?
```

In questo caso MQTT puo' essere ancora funzionante: il problema e' spesso il reporting LAN/Wi-Fi della power station che si e' congelato.

## Comportamento dei sensori

L'add-on usa MQTT discovery e pubblica `availability`, quindi sensori e controlli vanno offline quando il bridge non gira.

Alcuni sensori possono risultare `Sconosciuto` quando l'uscita corrispondente e' spenta o quando il dispositivo non invia quel dato nel report corrente.

## Debug

Per indagare problemi di connessione o decoding, imposta:

```yaml
log_level: debug
```

Non pubblicare log o opzioni contenenti credenziali, token, LAN key o password.
