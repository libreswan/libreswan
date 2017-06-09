#!/bin/bash

set -e

thisDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $thisDir

if [ "$1" != "build" ] && [ "$1" != "pull" ] && [ "$1" != "push" ]; then
  echo "Usage: $0 DIRECTORY" >&2
  exit 1
fi

