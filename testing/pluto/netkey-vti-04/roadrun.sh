ipsec auto --up road-eastnet
ping -n -c 4 192.0.2.254
# on east, run: ip route add 192.1.3.194/32 dev ipsec0
echo done
