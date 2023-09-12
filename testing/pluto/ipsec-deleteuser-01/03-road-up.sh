ipsec whack --xauthname 'use1' --xauthpass 'use1pass' --name xauth-road-eastnet --initiate
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
