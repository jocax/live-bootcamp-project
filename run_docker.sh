#!/bin/zsh

docker run --name ps-db -e POSTGRES_PASSWORD=[YOUR_POSTGRES_PASSWORD] -p 5432:5432 -d postgres:15.2-alpine
