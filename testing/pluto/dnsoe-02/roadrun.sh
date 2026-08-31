ipsec whack --oppohere 192.1.3.209 --oppothere east.testing.libreswan.org
# should show established tunnel and no bare shunts
ipsec trafficstatus
ipsec shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
ipsec shuntstatus
echo done
