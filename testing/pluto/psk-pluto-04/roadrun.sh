ipsec whack --debug-all
ipsec auto --up road-east-psk
ping -n -c 4 192.1.2.23
ipsec whack --trafficstatus
echo done
