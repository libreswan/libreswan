# sleep a little to allow north to establish tunnel to east
sleep 20
ipsec auto --up westnet-northnet-ipv4-psk
../../guestbin/ping-once.sh --up -I 192.0.1.254 198.18.66.254
echo done
