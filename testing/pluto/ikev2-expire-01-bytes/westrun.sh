ipsec auto --up west

: ==== cut ====
ip -s xfrm state
: ==== tuc ====

# find out the actual number of bytes
actual=$(sed -n -e 's/.* ipsec-max-bytes.* actual-limit=\([0-9]*\).*/\1/ p' /tmp/pluto.log | head -1)
echo $actual

# First take the SA up-to, but not over, the limit by spraying the
# peer with ping packets.
#
# Second, slowly drip packets into the SA until the trafficstatus for
# the state disappears indicating a replace/rekey.

spray() { local n=0 ; while test $n -lt $1 ; do  n=$((n + 1)) ; ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; done ; }
drip() { while ipsec trafficstatus | grep -e "$1" ; do ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 ; sleep 5 ; done ; }

# once

spray $((actual / 84))
drip '#2'

# twice

spray $((actual / 84))
drip '#3'

# thrice

spray $((actual / 84))
drip '#4'
