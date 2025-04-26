ipsec auto --up west1
ipsec auto --up west2
ipsec auto --up west3
# ping will fail until we fix  up-client-v6 and add source address.
../../guestbin/ping-once.sh --up -I 2001:db8:0:3:1::0 2001:db8:0:2::254
echo done
