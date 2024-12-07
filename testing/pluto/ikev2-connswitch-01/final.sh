../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# on east expect a switch away from distraction
grep -e '^"distraction".*switched' /tmp/pluto.log
