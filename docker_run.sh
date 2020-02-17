#!/usr/bin/env sh

if [ ! -e database.db ]; then
	touch ./database.db
fi

mkdir -p ./results/
mkdir -p ./map/static/data/

docker-compose up -d map
docker-compose run grinder
