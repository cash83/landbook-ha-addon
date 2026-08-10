ARG BUILD_FROM
FROM ${BUILD_FROM}

# tzdata: senza, time.localtime() nel container e' UTC e tutti gli orari nel log
# (FREEZE START / UNREACHABLE START) risultano 2h indietro rispetto a Home
# Assistant, rendendo impossibile incrociarli con la history. Il Supervisor
# passa gia' la variabile TZ agli add-on: serve solo il database dei fusi.
RUN apk add --no-cache python3 py3-pip py3-pycryptodome py3-requests py3-paho-mqtt tzdata

# Il Supervisor NON passa TZ a questo add-on (verificato sul campo: la variabile
# arriva vuota), quindi senza questo default il container resta su UTC. Si puo'
# sovrascrivere con l'opzione `timezone` dell'add-on.
ENV TZ=Europe/Rome

WORKDIR /app
COPY landbook_ha_mqtt_bridge.py landbook_local_client.py landbook_lan_probe.py addon_run.py /app/
COPY landbook_ttlv_walker.py landbook_tsl_discovery.py /app/
COPY wf_autodiscovery.py wf_socket_cloud.py wf_privacy.py platforms.json config.yaml /app/
COPY landbook/ /app/landbook/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
