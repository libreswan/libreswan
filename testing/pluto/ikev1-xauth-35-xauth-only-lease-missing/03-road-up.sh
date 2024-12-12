ipsec whack --xauthname 'gooduser90' --xauthpass 'use1pass' --name road-east --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
ipsec whack --trafficstatus
