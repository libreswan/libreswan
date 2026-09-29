ipsec whack --xauthname 'xroad' --xauthpass 'use1pass' --name road-east --initiate # sanitize-retransmits
# bonus ping for different count
../../guestbin/ping-once.sh --up -I 192.0.2.102 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.2.102 192.0.2.254
ipsec trafficstatus
echo done
