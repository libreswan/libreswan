ipsec whack --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
ipsec whack --trafficstatus
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
