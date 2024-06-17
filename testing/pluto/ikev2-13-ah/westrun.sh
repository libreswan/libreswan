ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# test rekey
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
# test delete
ipsec down westnet-eastnet-ipv4-psk-ikev2
echo done
