ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --listpubkeys
# test delete/free
ipsec auto --delete westnet-eastnet-ikev2
echo done
