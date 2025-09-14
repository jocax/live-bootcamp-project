#!/bin/zsh
# We use port 5433 on local host
docker run --name letsgetrusty-db -e POSTGRES_PASSWORD=postgres -p 5434:5432 -d postgres:17.2-alpine && (trap 'docker stop letsgetrusty-db && docker rm letsgetrusty-db' INT; docker logs -f letsgetrusty-db)

