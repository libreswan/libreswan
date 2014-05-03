ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-east --initiate
ipsec eroute
ping -n -c 4 192.0.2.254
echo done.

