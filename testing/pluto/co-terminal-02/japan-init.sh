#!/bin/sh

: ==== start ====

set -x
CFG="--config /testing/pluto/co-terminal-02/japan.conf" export CFG
: just for when we run it interactively
ipsec setup $CFG stop

rndc stop >/dev/null 2>&1
named






