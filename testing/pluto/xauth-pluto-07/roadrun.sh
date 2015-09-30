ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate
ipsec eroute
ping -n -c4 192.0.2.254
ipsec eroute
echo done.
