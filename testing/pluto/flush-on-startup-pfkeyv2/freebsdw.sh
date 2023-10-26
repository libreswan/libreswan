../../guestbin/netbsd-prep.sh # note: swan-prep does not yet support BSD
ipsec initnss

# add a policy + state
setkey -f setkey.in

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# start pluto
ipsec pluto --config /usr/local/etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started

# check policy/state gone
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
