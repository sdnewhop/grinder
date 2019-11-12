#!/usr/bin/env sh

pwd=$(pwd)

if [ ! -e database.db ]; then
	touch ${pwd}/database.db
fi

mkdir -p ./results/
mkdir -p ./map/static/data/

docker run -it --rm \
	-p 5000:5000 \
	--volume ${pwd}/database.db:/app/database.db \
	--volume ${pwd}/results:/app/results \
	--volume ${pwd}/map/static/data:/app/map/static/data \
	grinder-framework
