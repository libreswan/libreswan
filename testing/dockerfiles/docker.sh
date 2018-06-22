#!/bin/bash

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(basename "$0")"

cd "$DIR"

if [ "$1" != "build" ] && \
   [ "$1" != "pull" ] && \
   [ "$1" != "push" ] && \
   [ "$1" != "list" ]; then
  echo -e "Usage: $BASE arg\n" \
          "arg should be build, pull, push or list"  >&2
  exit 1
fi

for dir in */*; do
  DOCIMG=$(printf "$dir\n" | sed 's#/##' | sed 's#^#curtine/libreswan:#')

  if [ "$1" == "build" ]; then
    /bin/bash -c "cd $dir && docker build -t $DOCIMG ."
    continue
  fi

  if [ "$1" == "list" ]; then
    printf "$DOCIMG\n"
    continue
  fi

  docker "$1" "$DOCIMG"
done

