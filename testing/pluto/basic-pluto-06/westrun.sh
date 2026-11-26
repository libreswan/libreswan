ipsec up westnet-eastnet-ipv4-psk # sanitize-retransmits
../../guestbin/wait-for.sh --match '#2: IPsec SA established' -- cat OUTPUT/east.pluto.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
echo done
