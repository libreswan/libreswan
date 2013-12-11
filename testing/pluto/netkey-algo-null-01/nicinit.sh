#!/bin/sh

# Display the table, so we know it's correct.
iptables -t nat -L

echo done.
