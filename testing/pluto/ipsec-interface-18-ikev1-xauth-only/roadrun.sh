ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name road-east --initiate
ipsec trafficstatus
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo done
