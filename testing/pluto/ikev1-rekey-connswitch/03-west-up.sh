ipsec auto --up TUNNEL-A
ipsec auto --up TUNNEL-B
ipsec auto --up TUNNEL-C
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
ping -n -q -c 4 -I 192.0.1.254 192.0.2.244
ping -n -q -c 4 -I 192.0.1.254 192.0.2.234
#IKE sa will be on TUNNEL-A
ipsec auto --status | grep ISAKMP
