ipsec whack --impair ignore_soft_expire
ipsec auto --up west

# First take the SA up-to, but not over, the limit by spraying the
# peer with ping packets.
#
# Second, slowly drip packets into the SA until the trafficstatus for
# the state disappears indicating a replace/rekey.

spray() { local n=0 ; while test $n -lt $1 ; do  n=$((n + 1)) ; ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; done ; }
drip() { while ipsec trafficstatus | grep -e "$1" ; do ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; sleep 5 ; done ; }

# pings will not trigger a soft expire
spray 18

: ==== cut ====
ip -s xfrm state
: ==== tuc ====

# expect #2 IPsec original Child SA
ipsec trafficstatus

# now trigger soft expire
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# #2 will still around
ipsec trafficstatus

# now trigger hard expire
../../guestbin/fping-short.sh --lossy 15 -I 192.0.1.254 192.0.2.254
sleep 5
# expect #3 a new Child SA(not rekeyed). Rekey will not happen because of impair-soft-expire
../../guestbin/ipsec-trafficstatus.sh
echo done
