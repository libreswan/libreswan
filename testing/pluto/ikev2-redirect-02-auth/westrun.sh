ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair trigger-revival:1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
