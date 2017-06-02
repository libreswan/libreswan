ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23
# should show established tunnel and no bare shunts
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec whack --trafficstatus
echo done
