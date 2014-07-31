#!/bin/sh

thing=$1

until (ipsec eroute | grep '%'"$thing" > /dev/null)
do
    sleep 1
done


