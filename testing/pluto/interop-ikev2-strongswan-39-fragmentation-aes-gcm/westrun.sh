ipsec auto --up  westnet-eastnet-ikev2
ping -n -c4 -I 192.0.1.254 192.0.2.254
../../pluto/bin/ipsec-look.sh
grep "fragment number" /tmp/pluto.log
echo done
