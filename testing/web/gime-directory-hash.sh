#!/bin/sh

# Reverse engineer 2016-08-08-0556-3.18-51-g[00a7f80]-dirty-master

basename $1 | sed -n -e 's/.*-g\([^-]*\)-.*/\1/p'
