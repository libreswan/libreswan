ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
# AA see really weired route, I have to remove that
route -n
route del -net 192.1.2.23 netmask 255.255.255.255
ping -n -c 2 -I 192.0.2.1 192.1.2.23
echo done
