FROM python:3.6-alpine

RUN apk update && apk upgrade
RUN apk add --no-cache nmap nmap-scripts
RUN apk add --no-cache libpng freetype libstdc++ pkgconfig
RUN apk add --no-cache --virtual .build-deps gcc build-base python-dev libpng-dev musl-dev freetype-dev
RUN ln -s /usr/include/locale.h /usr/include/xlocale.h

COPY requirements.txt /code/requirements.txt
RUN pip install -r /code/requirements.txt

RUN apk del .build-deps

ENV PYTHONPATH="/code"
COPY custom_scripts/ /code/custom_scripts/
COPY grinder/ /code/grinder/
COPY map/ /code/map/
COPY plugins/ /code/plugins/
COPY queries/ /code/queries/
COPY tests/ /code/tests/
COPY grinder.py /code/grinder.py
RUN mkdir /code/results/

WORKDIR /code
ENTRYPOINT ["python3", "/code/grinder.py"]