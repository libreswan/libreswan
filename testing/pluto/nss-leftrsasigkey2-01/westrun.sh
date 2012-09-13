ipsec auto --up  westnet-eastnet-ipv4-rsa2
ipsec look
#ping -n -c 4 -I 192.0.1.254 192.0.2.254
# should work without -I, check _updown.klips / _updown.mast?
#ping -n -c 4 192.0.2.254
echo done
