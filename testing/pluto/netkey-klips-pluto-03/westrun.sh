ipsec auto --up  westnet-eastnet
# hitting the passthrough, goig out unencrypted, dropped by east
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo take-conn-encrypted | nc -s 192.0.1.254 192.0.2.254 22
echo done
