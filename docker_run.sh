#!/usr/bin/env sh

usage() {
	printf "Usage: %s [--cpus <quantity-of-cpu>] [-h | --help]" "$(basename "$0")"
}

user_cpu_count=1
cpu_count=0
pwd=$(pwd)

while [ $# -gt 0 ]; do
	case "$1" in
		"-h"|"--help") usage; exit 0 ;;
		"--cpus") user_cpu_count=$2; shift 2 ;;
		*) usage; exit 0 ;;
	esac
done

case "$(uname)" in
	"Linux") cpu_count=$(grep -c 'processor' /proc/cpuinfo) ;;
	"Darwin") cpu_count=$(sysctl -n hw.logicalcpu) ;;
	*) cpu_count=1 ;;
esac

if [ $user_cpu_count -gt $cpu_count ] || [ $cpu_count -eq 1 ]; then
	user_cpu_count=$cpu_count
fi

if [ $user_cpu_count -eq 0 ]; then
	user_cpu_count=$(echo "$cpu_count / 2" | bc)
fi

if [ ! -e database.db ]; then
	touch ./database.db
fi

mkdir -p ./results/
mkdir -p ./map/static/data/

docker run -it --rm \
	-p 5000:5000 \
	--cpus="$user_cpu_count" \
	--volume "${pwd}/database.db:/app/database.db" \
	--volume "${pwd}/results:/app/results" \
	--volume "${pwd}/map/static/data:/app/map/static/data" \
	grinder-framework
