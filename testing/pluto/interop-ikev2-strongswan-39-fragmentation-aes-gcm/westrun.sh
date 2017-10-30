ipsec auto --up  westnet-eastnet-ikev2
ping -n -c4 -I 192.0.1.254 192.0.2.254
ipsec look
grep "fragment number" /tmp/pluto.log
echo done
