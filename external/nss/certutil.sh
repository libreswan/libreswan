#!/bin/sh

root=$(realpath $(dirname $0))
set -x
LD_LIBRARY_PATH=${root}/dist/Debug/lib gdb --args ${root}/dist/Debug/bin/certutil "$@"
