# Landbook Home Assistant Add-on Repository

Home Assistant add-on repository for the Landbook FPPT-T2400 LAN MQTT Bridge.

![Landbook FPPT-T2400](landbook_ha_addon/images/landbook-fppt-t2400.png)

## Unofficial Project

This repository hosts a community Home Assistant add-on and is not affiliated
with, endorsed by, or sponsored by Wonderfree, Landbook, Landecia, Pecron, or
their manufacturers. Wonderfree, Landbook, Landecia and related trademarks
belong to their respective owners.

This add-on is provided as-is. Use it at your own responsibility. For official
device support, firmware support, or account issues, use the official apps and
vendor support channels.

## What This Add-on Does

`landbook_ha_addon` is a LAN-first MQTT bridge for compatible power stations.
At startup it uses the official cloud account only to discover the device LAN
key and TSL schema, then the normal runtime flow is local:

```text
Power station LAN/Wi-Fi locale -> add-on -> MQTT -> Home Assistant
```

That means sensors, switches, selects and numbers are created from the real TSL
codes exposed by the device and then updated over the local LAN connection.

## Official App Account Required

To use this add-on you must already have:

- an account in the official mobile app for your device
- the device already paired in that official app

The add-on uses the same credentials only to retrieve the LAN key and the TSL
schema automatically. It does not create a separate account and it does not
bypass the normal vendor registration flow.

## Add repository

In Home Assistant:

1. Go to **Settings -> Add-ons -> Add-on Store**.
2. Open the menu in the top right.
3. Select **Repositories**.
4. Add:

```text
https://github.com/cash83/landbook-ha-addon
```

## Add-on

- `landbook_ha_addon`: Landbook FPPT-T2400 LAN bridge with MQTT discovery.

The add-on asks for the Landbook app email/password in its options only so it can discover the LAN key automatically. Do not publish your add-on options or logs with private credentials.
