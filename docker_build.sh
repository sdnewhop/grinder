#!/usr/bin/env sh

docker build --target tls-scanner-build -t tls-scanner-build .
docker build -t grinder-framework .
