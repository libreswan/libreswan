# on east this should show 2 sets of in/fwd/out policies
../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# check both connections still work on east
hostname | grep east > /dev/null && ping -n -q -c 2 192.0.2.101
hostname | grep east > /dev/null && ping -n -q -c 2 192.0.2.102
ipsec whack --trafficstatus
