ipsec whack --xauthname 'use3' --xauthpass 'use1pass' --name modecfg-road-eastnet-psk --initiate # sanitize-retransmits
../../guestbin/wait-for.sh --match '#2: IPsec SA established' -- cat OUTPUT/east.pluto.log
ipsec trafficstatus
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo done
