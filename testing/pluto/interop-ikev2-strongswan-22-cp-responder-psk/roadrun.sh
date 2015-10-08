ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
route -n
#weired routes? are they rements of old opportunistic 
route del -net 128.0.0.0 netmask 128.0.0.0
route del -net 0.0.0.0 netmask 128.0.0.0
ping -n -c 2 -I 192.0.2.1 192.0.2.254
echo done
