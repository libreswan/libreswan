#!/bin/sh

../../guestbin/wait-for.sh --match "$1" -- cat /tmp/pluto.log
