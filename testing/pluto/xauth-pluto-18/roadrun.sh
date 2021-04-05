ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate
../../guestbin/ping-once.sh --up -I 192.0.2.209 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --up modecfg-road-eastnet-psk
../../guestbin/ping-once.sh --up -I 192.0.2.209 192.0.2.254
ipsec whack --trafficstatus
echo done
