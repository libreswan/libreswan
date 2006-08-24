#!/bin/sh

: ==== start ====
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

#ipsec klipsdebug --set pfkey
ROOT= export ROOT

sh $ROOT/testing/klips/saref-alloc-01/alloctest2.sh

ipsec spi | wc -l
: ==== end ====


