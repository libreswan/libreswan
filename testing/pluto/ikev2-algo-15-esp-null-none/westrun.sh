# should fail
ipsec auto --add westnet-eastnet-esp-null
# enable impair
ipsec whack --impair allow-null-null --impair ikev2-include-integ-none
ipsec auto --add westnet-eastnet-esp-null
ipsec auto --up westnet-eastnet-esp-null
ping -c4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
