#!/bin/sh

# don't run on nic, it does not have ipsec installed
hostname | grep "nic" > /dev/null && exit

# Dump the raw output from <<ip xfrm state|policy>> on stderr (putting
# it on stderr, makes it easier for calling scripts to discard it vis:
# <<ipsec-look.sh 2>/devnull|grep foo>>.  Internally, "ipsec look"
# uses that same output to produce its dump.

echo ==== cut ====	   				 1>&2
echo "start raw xfrm state:"				 1>&2
ip -o xfrm state     					 1>&2
echo "end raw xfrm state:"				 1>&2
echo "start raw xfrm policy:"				 1>&2
ip -o xfrm policy    					 1>&2
echo "end raw xfrm policy:"				 1>&2
echo ==== tuc ==== 					 1>&2

exec ipsec look "$@"
