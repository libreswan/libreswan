ipsec auto --up road-eastnet-nonat
ping -n -c 4 -I 192.0.2.219  192.0.2.254
ipsec whack --trafficstatus
../../pluto/bin/ipsec-look.sh
echo done
