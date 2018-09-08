ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
ping -n -c 4 -I 192.0.2.102 192.0.2.254
ipsec whack --trafficstatus
echo done
