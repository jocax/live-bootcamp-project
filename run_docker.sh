#!/bin/zsh

docker compose -f compose.build.yml build

# Set the COMPOSE_FILE environment variable
#export COMPOSE_FILE=compose.yml:compose.override.yml:compose.override.tls.yml

# Then just run
docker compose  -f compose.yml rm
docker compose  -f compose.yml -f compose.override.yml -f compose.override.tls.yml up
