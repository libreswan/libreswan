ipsec whack --impair add_unknown_v2_payload_to:IKE_INTERMEDIATE
ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
