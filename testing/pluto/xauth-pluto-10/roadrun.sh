ipsec whack --xauthpass 'use1pass' --name xauth-road-eastnet --initiate # sanitize-retransmits
ipsec trafficstatus
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
echo done
