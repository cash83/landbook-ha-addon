# Landbook LAN MQTT Bridge

## 0.3.20-switch-quarantine

Fix principale: evita comandi/switch casuali dopo reconnect LAN.

- Scarta per 20 secondi i comandi MQTT accumulati mentre la LAN era disconnessa.
- Accetta nuovi comandi solo dopo almeno 2 frame sensori LAN validi.
- Azzera eventuale output_power pendente al reconnect.
- Gli switch non vengono aggiornati da parole trovate nei frame LAN generici.
- Corregge lo stato: se batteria negativa e input 0, mostra In scarica invece di In carica.
- LAN resta veloce con subscription a 10s.

Home Assistant add-on for the Landbook FPPT-T2400 LAN MQTT bridge.

## Installazione locale

1. Copia la cartella `landbook_ha_addon` nella share degli add-on locali di Home Assistant.
2. In Home Assistant vai in **Impostazioni -> Add-on -> Add-on Store**.
3. Apri il menu in alto a destra e premi **Reload**.
4. Installa **Landbook LAN MQTT Bridge**.
5. Imposta `mqtt_password` e avvia l'add-on.

L'add-on usa MQTT discovery e pubblica `availability`, quindi sensori e controlli vanno offline quando il bridge non gira.


## 0.3.20-switch-quarantine

Fix anti-switch casuali:
- gli switch non vengono più aggiornati scandendo parole sparse nei frame LAN dei sensori;
- `dc`, `ac`, `grid`, `led`, `screen`, `beep` e `slow_reporting` cambiano stato solo dopo un comando MQTT reale o da stato iniziale/cache;
- disattivato l'azzeramento automatico dei sensori DC/AC basato su presunti stati switch;
- disattivato di default il retrigger automatico `grid OFF → ON` dopo E02;
- sensori LAN ancora veloci tramite subscription a 10 secondi; bus_refresh reso unico ogni 30 secondi e battery_mask ogni 60 secondi senza refresh doppio.

Opzioni debug, lasciarle `false` in uso normale:
- `lan_switch_state_from_reports`;
- `enable_grid_fault_recovery`.