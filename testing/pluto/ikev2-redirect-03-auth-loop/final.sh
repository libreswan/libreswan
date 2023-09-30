sleep 2
../../guestbin/ipsec-kernel-state.sh ; ../../guestbin/ipsec-kernel-policy.sh
# confirm east is in unrouted state again
hostname | grep east > /dev/null && ipsec status |grep "eroute owner"
