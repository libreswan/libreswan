ipsec up westnet-eastnet # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down westnet-eastnet
echo done
