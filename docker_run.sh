#!/usr/bin/env sh

# Create markers file if it not exists
if [ ! -e ./map/static/data/markers.json ]; then
  echo "{}" > ./map/static/data/markers.json
fi

# Create database file if it not exists
if [ ! -e database.db ]; then
	touch ./database.db
fi

# Create required directories
mkdir -p ./results/
mkdir -p ./map/static/data/

# Run it all
docker-compose up -d map
docker-compose run grinder
