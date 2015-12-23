# sleep a little to allow north to establish tunnel to east
sleep 20
ipsec auto --up westnet-northnet-ipv4-psk
ping -n -c 4  -I 192.0.1.254 192.0.3.254
echo done
