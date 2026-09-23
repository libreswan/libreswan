ipsec up westnet-eastnet-sourceip # sanitize-retransmits
# not using -I because sourceip= should add the route
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
