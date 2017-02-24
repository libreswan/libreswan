
ipsec auto --add westnet-eastnet-ikev2-dh19
ipsec auto --up  westnet-eastnet-ikev2-dh19
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --down  westnet-eastnet-ikev2-dh19
ipsec auto --delete  westnet-eastnet-ikev2-dh19

ipsec auto --add westnet-eastnet-ikev2-dh20
ipsec auto --up  westnet-eastnet-ikev2-dh20
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --down  westnet-eastnet-ikev2-dh20
ipsec auto --delete  westnet-eastnet-ikev2-dh20

ipsec auto --add westnet-eastnet-ikev2-dh21
ipsec auto --up  westnet-eastnet-ikev2-dh21
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --down  westnet-eastnet-ikev2-dh21
ipsec auto --delete  westnet-eastnet-ikev2-dh21

echo done
