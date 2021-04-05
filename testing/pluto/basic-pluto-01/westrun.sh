ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# test that af_key.ko is not loaded or in use. af_key.ko creates /proc/net/pfkey
test -f /proc/net/pfkey && echo "af_key.ko should not have been loaded"
echo done
