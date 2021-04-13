ipsec auto --up westnet-eastnet-ikev2
# first pings hit regular ESP since pings too small to compress
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
# this oddly shows up as 0 packets and 4 packets on ipcomp
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"
# test compression via large pings that can be compressed on IPCOMP SA
ping -n -q -c 4 -s 8184  -p ff -I 192.0.1.254 192.0.2.254
# this then  shows up as 4 packets and 8 packets on ipcomp
ip -o -s xfrm state|grep "proto comp" | sed "s/^\(.*\)\(lifetime current:.*\)\(add .*$\)/\2/"
# We cannot run ipsec whack --trafficstatus because compression causes the byte count to slightly differ each run
echo done
