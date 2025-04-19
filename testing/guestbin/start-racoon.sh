#!/bin/sh

# Start racoon and then wait for it to open it's socket see NetBSD bug
# 59330.

rm -f /tmp/racoon.log
ln -s $PWD/OUTPUT/$(hostname).racoon.log /tmp/racoon.log

racoon -l /tmp/racoon.log

# wait for the socket to appear

while test ! -r /var/run/racoon.sock ; do
    sleep 1
done
