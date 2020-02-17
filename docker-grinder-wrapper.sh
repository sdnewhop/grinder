#!/usr/bin/env sh

export PS1="(grinder-docker) $PS1"

host="0.0.0.0"
port="5000"

cd ./map/ && {
	flask run --host=$host --port=$port > /dev/null 2>&1 &
	flask_pid=$!
	cd ..
}

printf "\e[1mWelcome to\e[0m\n"
./grinder.py -h

sh

[ -n "$flask_pid" ] && kill $flask_pid
