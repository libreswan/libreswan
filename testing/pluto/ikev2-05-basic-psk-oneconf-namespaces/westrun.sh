ipsec up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down westnet-eastnet-ipv4-psk-ikev2

grep 'PLUTO_INBYTES=[1-9][0-9]*' /tmp/pluto.log || echo "Error: traffic counters not passed to updown!"
echo done
