ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# wait for 30s rekey
sleep 20
ping -n -c 4 -I 192.0.1.254 192.0.2.254
sleep 20
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# expecting X
grep established /tmp/pluto.log
echo done
