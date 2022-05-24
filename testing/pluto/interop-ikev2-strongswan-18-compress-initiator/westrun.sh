strongswan up westnet-eastnet-ikev2

# First ping is regular ESP since ping is too small to compress.  This
# oddly shows up as 0 packets and 4 packets on ipcomp.
../../guestbin/ping-once.sh --up --small -I 192.0.1.254 192.0.2.254
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"

# Finally, a packet that is both larger than the MTU and compression
# friendly.  This then shows up as 4 packets and 8 packets on ipcomp.
../../guestbin/ping-once.sh --up --large -I 192.0.1.254 192.0.2.254
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"

# mangled traffic status
ipsec whack --trafficstatus | sed -e 's/Bytes=\([0-9]\)[0-9][0-9],/Bytes=\1nn,/g'
