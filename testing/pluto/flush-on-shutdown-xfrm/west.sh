/testing/guestbin/swan-prep --46 --nokey

# expect no holes; not ipsec-kernel-policy.sh as that filters
ipsec _kernel policy

ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started

# expect holes; not ipsec-kernel-policy.sh as that filters
ipsec _kernel policy

ipsec whack --shutdown
# expect no holes; not ipsec-kernel-policy.sh as that filters
ipsec _kernel policy
