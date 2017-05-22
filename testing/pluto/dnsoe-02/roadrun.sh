ipsec whack --oppohere 192.1.3.209 --oppothere east.testing.libreswan.org
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
