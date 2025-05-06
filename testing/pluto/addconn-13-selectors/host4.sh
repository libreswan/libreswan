#!/bin/sh

RUN() {
    echo " $@" 1>&2
    "$@"
}

name=$1 ; shift

RUN ipsec addconn --name ${name} \
    leftid=@west \
    rightid=@east \
    left=192.1.2.45 \
    right=192.1.2.23 "$@"

RUN ipsec connectionstatus ${name} | grep '\.\.\.'
