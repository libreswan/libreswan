/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east
# we cannot have --impair retransmit, because for some reason
# first IKE_AUTH request road sends is actually retransmitted once.
ipsec whack --impair revival
echo initdone
ipsec auto --up road-east
echo "1. road connection add+up done"
sleep 1
# should be connected to west!
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --delete road-east
echo "1. road connection delete done"
