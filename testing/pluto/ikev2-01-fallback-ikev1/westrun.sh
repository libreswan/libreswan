ipsec auto --up  westnet-eastnet-ikev2
# there is an extra set of unexplained retry in IKEv2 before it falls back to IKEv1
sleep 60 
ping -n -c 2 -I 192.0.1.254 192.0.2.254
echo done
