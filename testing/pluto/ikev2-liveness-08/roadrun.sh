ipsec auto --up road-east-x509-ipv4
ping -n -q -c 4 -I 192.0.2.101 192.1.2.23
ipsec whack --trafficstatus
ping -n -q -c 60 -I 192.0.2.101 192.1.2.23
ipsec whack --trafficstatus
echo "initdone"
