ipsec auto --up westnet-eastnet-ipcomp

# First ping hit regular ESP since pings too small to compress.  This
# oddly shows up as 0 packets and 4 packets on ipcomp.
../../guestbin/ping-once.sh --up --small -I 192.0.1.254 192.0.2.254
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"

# Finally test compression via large pings that can be compressed on
# IPCOMP SA.  This then shows up as 4 packets and 8 packets on ipcomp.
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"

# Need to edit packets.
ipsec whack --trafficstatus | sed -e 's/Bytes=\([0-9]\)[0-9][0-9],/Bytes=\1nn,/g'
