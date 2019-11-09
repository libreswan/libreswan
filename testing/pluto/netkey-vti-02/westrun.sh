ipsec auto --up  westnet-eastnet-vti-01
ipsec auto --up  westnet-eastnet-vti-02
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 10.0.1.254 10.0.2.254
ipsec whack --trafficstatus
echo done
