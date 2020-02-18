# Build TLS-Scanner
FROM maven:3-jdk-8 AS tls-scanner-build

RUN git clone --depth=1 --branch '3.1' https://github.com/RUB-NDS/TLS-Attacker.git && \
	git clone --depth=1 --recurse-submodules --branch '2.9' https://github.com/RUB-NDS/TLS-Scanner.git && \
	(cd /TLS-Attacker/ && mvn clean install -DskipTests=true) && \
	(cd /TLS-Scanner/ && mvn clean install -DskipTests=true)

# Build Grinder Framework
FROM python:3.7-alpine AS grinder-framework-build

LABEL org.label-schema.name="Grinder Framework" \
      org.label-schema.description="Python framework to automatically discover and enumerate hosts" \
      org.label-schema.license="GPL-2.0"

COPY . /app/
COPY /docker/grinder/entrypoint.sh /app/entrypoint.sh
COPY --from=tls-scanner-build /TLS-Scanner/apps /app/TLS-Scanner/apps

RUN apk add --no-cache nmap nmap-scripts && \
	apk add --no-cache libpng freetype libstdc++ pkgconfig openjdk8 && \
	apk add --no-cache --virtual .build-deps gcc build-base python-dev libpng-dev musl-dev freetype-dev && \
	ln -s /usr/include/locale.h /usr/include/xlocale.h && \
	pip install --no-cache-dir -r /app/requirements.txt && \
	pip uninstall -y flask && \
	apk del .build-deps && \
	ln -s /app/grinder.py /usr/local/bin/grinder && \
	mkdir -p /app/results/ && \
	mkdir -p /app/map/static/data/ && \
	rm -rf /etc/apk/cache && \
	chmod +x /app/entrypoint.sh

WORKDIR /app
ENV PYTHONPATH="/app"
EXPOSE 5000
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
