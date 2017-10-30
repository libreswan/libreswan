#!/bin/sh

set -eu

# need to generate an empty array when no arguments
for d in "$@"; do
    jq '.directory = (input_filename|split("/")|.[-2])' \
       $(realpath ${d})
done | jq -s .
