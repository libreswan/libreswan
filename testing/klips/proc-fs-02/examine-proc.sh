#!/bin/sh
TZ=GMT export TZ

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

rmmod ipsec

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

insmod /ipsec.o

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

rmmod ipsec

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

insmod /ipsec.o

ls -l /proc/net/ipsec_*
find /proc/net/ipsec -ls

