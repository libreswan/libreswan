ipsec auto --add north-east
ipsec whack --xauthname 'xnorth' --xauthpass 'use1pass' --name north-east --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.201 192.0.2.254
ipsec whack --trafficstatus
