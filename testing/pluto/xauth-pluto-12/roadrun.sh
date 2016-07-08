ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate
ping -n -c 4 -I 192.0.2.209 192.0.2.254
ipsec whack --trafficstatus
echo done
