ipsec auto --up westnet-eastnet-compress
# this ping wont be compressed
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
# test compression via large pings that can be compressed on IPCOMP SA
ping -n -q -c 4 -s 8184  -p ff -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-look.sh
ipsec auto --down westnet-eastnet-compress
echo done
