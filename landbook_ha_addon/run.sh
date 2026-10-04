#!/bin/sh
set -eu
echo "[Landbook LAN MQTT Bridge] booting..."
exec python3 -u /app/test_powerstation.py
