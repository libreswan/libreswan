ipsec whack --impair revival

ipsec up westnet-eastnet-ipv4-psk-ikev2 # sanitize-retransmits
ipsec whack --impair trigger_revival:1 # sanitize-retransmits

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
