# next one will fail because server will timeout for this user
ipsec whack --xauthname 'gooduser90' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
# next one should succed and ping pass throguh
ipsec auto --add xauth-road-eastnet
ipsec whack --xauthname 'gooduser' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
ping -w 4 -n -c4 192.0.2.254
ipsec whack --trafficstatus
echo done
