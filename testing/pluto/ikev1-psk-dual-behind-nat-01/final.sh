# on east this should show 2 sets of in/fwd/out policies
ipsec _kernel state
ipsec _kernel policy
# check both connections still work on east
hostname | grep east > /dev/null && ../../guestbin/ping-once.sh --up 192.0.2.101
hostname | grep east > /dev/null && ../../guestbin/ping-once.sh --up 192.0.2.102
ipsec whack --trafficstatus
