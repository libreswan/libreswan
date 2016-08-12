#!/bin/sh

# Reverse enginee 2016-08-08-0556-3.18-51-g00a7f80-dirty-master

echo $1 | sed -e 's/.*-g\([^-]*\)-.*/\1/'
