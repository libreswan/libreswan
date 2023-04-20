ipsec auto --delete TUNNEL-B
#TUNNEL-A and TUNNEL-C IPsec states remain. TUNNEL-B should be gone.
ipsec auto --status | grep TUNNEL
echo done
