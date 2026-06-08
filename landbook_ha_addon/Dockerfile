ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip py3-pycryptodome py3-requests

WORKDIR /app
COPY landbook_ha_mqtt_bridge.py landbook_local_client.py landbook_lan_probe.py addon_run.py /app/
COPY wf_autodiscovery.py wf_privacy.py platforms.json /app/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
