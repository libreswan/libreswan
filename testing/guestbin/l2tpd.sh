#!/bin/sh

cd /tmp
xl2tpd -D 2>/tmp/xl2tpd.log &

# give it a chance to start
sleep 1

