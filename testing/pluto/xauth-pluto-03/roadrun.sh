ipsec whack --xauthname 'use1' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
ping -n -c4 192.0.2.254
ipsec whack --trafficstatus
echo done
