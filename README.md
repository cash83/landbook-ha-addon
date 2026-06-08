# Landbook Home Assistant Add-on Repository

Home Assistant add-on repository for the Landbook FPPT-T2400 LAN MQTT Bridge.

![Landbook FPPT-T2400](landbook_ha_addon/images/landbook-fppt-t2400.png)

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
