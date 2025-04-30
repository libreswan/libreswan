ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
ipsec whack --trafficstatus
ipsec down road-east
ipsec delete road-east

ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-narrows-east --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
ipsec whack --trafficstatus
