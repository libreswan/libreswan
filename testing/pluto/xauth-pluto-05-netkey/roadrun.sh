ipsec auto --replace modecfg-road-eastnet-psk
ipsec whack --status | grep modecfg-road-eastnet-psk
ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate
ping -c4 192.0.2.254
echo done.
