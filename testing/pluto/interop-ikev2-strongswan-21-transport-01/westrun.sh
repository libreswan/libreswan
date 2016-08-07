ipsec auto --up westnet-eastnet-ikev2
ping -n -c 4 -I 192.1.2.45 192.1.2.23
echo done
