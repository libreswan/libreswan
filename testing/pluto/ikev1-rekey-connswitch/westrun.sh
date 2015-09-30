ipsec auto --up TUNNEL-A
ipsec auto --up TUNNEL-B
ipsec auto --up TUNNEL-C
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 192.0.1.254 192.0.2.244
ping -n -c 4 -I 192.0.1.254 192.0.2.234
#IKE sa will be on TUNNEL-A
ipsec auto --status | grep ISAKMP
sleep 60
#IKE sa will be on TUNNEL-B
ipsec auto --status | grep ISAKMP
ipsec auto --down TUNNEL-B
#One IKE will remain on TUNNEL-B
ipsec auto --status | grep TUNNEL
ipsec auto --delete TUNNEL-B
#TUNNEL-A and TUNNEL-C IPsec states remain. TUNNEL-B should be gone.
ipsec auto --status | grep TUNNEL
echo done
