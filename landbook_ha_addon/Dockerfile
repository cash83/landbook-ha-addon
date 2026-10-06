ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip py3-pycryptodome py3-requests py3-paho-mqtt tzdata

ENV TZ=Europe/Rome

WORKDIR /app
COPY landbook_bridge.py platforms.json /app/
COPY landbook_app /app/landbook_app/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
