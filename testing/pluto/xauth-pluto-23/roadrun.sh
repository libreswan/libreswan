../../guestbin/block-non-ipsec.sh
ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo done
