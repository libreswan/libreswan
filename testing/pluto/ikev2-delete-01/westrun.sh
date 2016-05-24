ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --status
ipsec whack --deletestate 1
sleep 2
ipsec auto --status
echo done
