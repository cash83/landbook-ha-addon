ARG BUILD_FROM
FROM ${BUILD_FROM}

# tzdata: senza, time.localtime() nel container e' UTC e tutti gli orari del log
# risultano indietro rispetto a Home Assistant, rendendo impossibile incrociarli
# con la history.
RUN apk add --no-cache python3 py3-pip py3-pycryptodome py3-requests py3-paho-mqtt tzdata

# Il Supervisor NON passa TZ a questo add-on (verificato sul campo: la variabile
# arriva vuota), quindi senza questo default il container resta su UTC. Si puo'
# sovrascrivere con l'opzione `timezone` dell'add-on, che il codice applica
# all'avvio con time.tzset().
ENV TZ=Europe/Rome

WORKDIR /app
COPY test_powerstation.py platforms.json /app/
COPY test_powerstation_app /app/test_powerstation_app/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
