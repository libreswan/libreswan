ipsec auto --replace modecfg-road-eastnet-psk
ipsec whack --status | grep modecfg-road-eastnet-psk
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate
ipsec whack --trafficstatus
ping -n -c4 192.0.2.254
ipsec whack --trafficstatus
echo done
