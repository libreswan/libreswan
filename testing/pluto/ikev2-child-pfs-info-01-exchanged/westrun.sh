ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# rekey to prove the KE proposed is used
ipsec whack --rekey-child --name westnet-eastnet-ikev2
echo done
