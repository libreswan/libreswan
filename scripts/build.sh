#!/bin/bash

set -eu

if [ $(uname) == "Linux" ]; then
  sudo apt -qq update
  sudo apt install -y libnspr4-dev
fi

make all
make install

