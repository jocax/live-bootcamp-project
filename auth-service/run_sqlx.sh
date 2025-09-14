#!/bin/zsh

# https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode-with-query

sqlx database create

sqlx migrate run
