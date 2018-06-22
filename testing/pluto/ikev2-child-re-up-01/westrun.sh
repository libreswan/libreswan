ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
sleep 5
# this should cause a rekey-or-reauth
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
sleep 3
# there should not be two tunnels EVENT_SA_REPLACE?
ipsec status |grep STATE
echo done
