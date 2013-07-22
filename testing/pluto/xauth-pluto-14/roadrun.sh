ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-east --initiate
ipsec eroute
ping -n -c 4 -I 192.0.2.100 192.0.2.254
echo done
