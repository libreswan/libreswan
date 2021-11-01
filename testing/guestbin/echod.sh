#!/bin/sh

# see https://github.com/nmap/nmap/issues/962 for why
# ncat doesn't cut it.

socat -v tcp-l:7,fork exec:'/bin/cat' > OUTPUT/echod.log 2>&1 &
