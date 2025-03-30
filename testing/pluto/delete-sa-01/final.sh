ipsec _kernel state
ipsec _kernel policy
# up to 3.26 we printed a bogus message, this is checking that no longer happens
grep "received and ignored empty informational" /tmp/pluto.log
