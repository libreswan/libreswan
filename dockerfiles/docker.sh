#!/bin/bash

set -e

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base="$(basename "$0")"

cd "$dir"

if [ "$1" != "build" ] && [ "$1" != "pull" ] && [ "$1" != "push" ] && \
   [ "$1" != "list" ]; then
  echo -e "Usage: $base arg\n" \
          "arg should be build, pull, push or list"  >&2
  exit 1
fi

for dir in */*; do
  docImg=$(printf "$dir" | sed 's#/#:#' | sed 's#^#curtine/libreswan-#')

  if [ "$1" == "list" ]; then
    printf "$docImg\n"
    continue
  fi

  if [ "$1" == "build" ]; then
    docker build -t "$docImg" "$dir"
    continue
  fi

  docker "$1" "$docImg"
done

