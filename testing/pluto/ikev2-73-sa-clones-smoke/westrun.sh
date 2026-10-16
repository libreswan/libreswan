# bring up the connection with clones=3.
#
# West is the initiator, so it creates the Additional Child SAs.  The
# test node has a single CPU, so clones=3 is reduced to 1 Additional
# Child SA (bound to CPU 0). Expect the Initial Child SA (#2) plus one
# Additional Child SA (#3).
ipsec auto --up westnet-eastnet-clones

# wait for the one Additional Child SA (#3) to be established (the
# helper's matched log line is discarded as it carries a timestamp)
../../guestbin/wait-for-pluto.sh '#3: initiator established Child SA' > /dev/null

# traffic must flow over the tunnel
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

# rekey the Initial Child SA; this recreates the Additional Child SA
ipsec whack --rekey-child --name westnet-eastnet-clones

# wait for the recreated Additional Child SA (#5) to be established
../../guestbin/wait-for-pluto.sh '#5: initiator established Child SA' > /dev/null

# traffic must still flow after the rekey
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

# tearing down the connection must delete Initial + Additional SAs
ipsec auto --down westnet-eastnet-clones
ipsec whack --trafficstatus
echo done
