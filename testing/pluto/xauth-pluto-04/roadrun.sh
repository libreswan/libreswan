ipsec whack --xauthname 'use2' --xauthpass 'use1pass' --name xauth-road-eastnet-psk --initiate
sleep 5
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
