ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23

# should show established tunnel and no bare shunts
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel state
ipsec _kernel policy
echo done
