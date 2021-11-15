#!/bin/sh

# don't run on nic, it does not have ipsec installed
hostname | grep "nic" > /dev/null && exit

# Dump the raw output from <<ip xfrm state|policy>> on stderr (putting
# it on stderr, makes it easier for calling scripts to discard it vis:
# <<ipsec-look.sh 2>/devnull|grep foo>>.  Internally, "ipsec look"
# uses that same output to produce its dump.

f=OUTPUT/$(hostname).ipsec-look.$$.log
echo ==== cut ====	   				1>&2
echo DUMP IN: $f   				 	1>&2
echo ==== tuc ====	   				1>&2

(
    echo "IP XFRM STATE:"
    ip -o xfrm state
    echo "IP XFRM POLICY:"
    ip -o xfrm policy
) > $f

exec ipsec look "$@"
