#!/usr/bin/env sh

export PS1="(grinder-docker) $PS1"

host="0.0.0.0"
port="5000"

cd ./map/
flask run --host=$host --port=$port >& /dev/null &
flask_pid=$!
cd ..

./grinder.py -h

sh

kill $flask_pid
