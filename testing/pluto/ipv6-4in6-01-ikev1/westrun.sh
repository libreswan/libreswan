ipsec auto --up westnet-eastnet-4in6
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
