echo road-ping
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
# note there should NOT be any incomplete IKE SA attempting to do ModeCFG
ipsec showstates

