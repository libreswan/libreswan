ipsec auto --up westnet-eastnet-twofish
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec look
echo done
