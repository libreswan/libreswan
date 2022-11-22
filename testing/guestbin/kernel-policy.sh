#!/bin/sh

# Dump the raw output from <<ip xfrm state|policy>> on stderr (putting
# it on stderr, makes it easier for calling scripts to discard it vis:
# <<ipsec-look.sh 2>/devnull|grep foo>>.  Internally, "ipsec look"
# uses that same output to produce its dump.

case $(uname) in
    Linux) exec ip xfrm policy ;;
    NetBSD|FreeBSD) exec setkey -DP ;;
    OpenBSD) exec ipsecctl -k -v -v -s flow ;;
    *) echo unknown ; exit 1 ;;
esac
