ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ping -n -c 2 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
# create havoc
ipsec whack --impair send-no-delete
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ping -n -c 4 -I 192.0.2.1 192.1.2.23
ipsec whack --trafficstatus
echo done
