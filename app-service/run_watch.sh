#!/bin/zsh

cargo watch -q -c -w src/ -w assets/ -w templates/ -x run
