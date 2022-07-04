ipsec whack --impair ignore-soft-expire
ipsec auto --up west
# pings will not trigger a soft expire
ping -n -q -c 18 -I 192.0.1.254 192.0.2.254
: ==== cut ====
ip -s xfrm state
: ==== tuc ====
# expect #2 IPsec original Child SA
ipsec trafficstatus
# now trigger soft expire
ping -n -q -c 8 -I 192.0.1.254 192.0.2.254
# #2 will still around
ipsec trafficstatus
# now trigger hard expire
../../guestbin/fping-short.sh --lossy 15 -I 192.0.1.254 192.0.2.254
sleep 5
# expect #3 a new Child SA(not rekeyed). Rekey will not happen because of impair-soft-expire
../../guestbin/ipsec-trafficstatus.sh
echo done
