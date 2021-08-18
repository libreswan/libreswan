ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
sleep 2
ping -n -q -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
