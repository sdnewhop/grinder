FROM maven:3.6.1-jdk-8 AS tls-scanner-build

RUN git clone --depth=1 https://github.com/RUB-NDS/TLS-Attacker.git && \
	git clone --depth=1 --recurse-submodules https://github.com/RUB-NDS/TLS-Scanner.git && \
	(cd /TLS-Attacker/ && mvn clean install -DskipTests=true) && \
	(cd /TLS-Scanner/ && mvn clean install -DskipTests=true)


FROM python:3.6-alpine

COPY . /app/
COPY --from=tls-scanner-build /TLS-Scanner/apps /app/TLS-Scanner/apps

WORKDIR /app

RUN apk update && apk upgrade && \
	apk add --no-cache nmap nmap-scripts && \
	apk add --no-cache libpng freetype libstdc++ pkgconfig openjdk8 && \
	apk add --no-cache --virtual .build-deps gcc build-base python-dev libpng-dev musl-dev freetype-dev && \
	ln -s /usr/include/locale.h /usr/include/xlocale.h && \
	pip install --no-cache-dir -r /app/requirements.txt && \
	apk del .build-deps && \
	ln -s /app/grinder.py /usr/local/bin/grinder && \
	mkdir -p /app/results/ && \
	mkdir -p /app/map/static/data/

ENV PYTHONPATH="/app"

EXPOSE 5000

ENTRYPOINT ["/bin/sh", "/app/docker-grinder-wrapper.sh"]
