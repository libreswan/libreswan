# next one will fail because server will timeout for this user
ipsec whack --xauthname 'gooduser90' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate #retransmits
# next one should succed and ping pass throguh
# prevent false positive on deleting I1 or I2 by redirecting to /dev/null
ipsec auto --add xauth-road-eastnet > /dev/null
ipsec whack --xauthname 'gooduser' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
echo done
