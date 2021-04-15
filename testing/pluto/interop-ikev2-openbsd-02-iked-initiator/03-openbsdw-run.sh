ping -n -q -c 1 -I 192.0.1.254 192.0.2.254
sleep 3
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
ipsecctl -s all | sort 
