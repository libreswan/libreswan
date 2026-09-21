sleep 2
ipsec _kernel state
ipsec _kernel policy
# confirm east is in unrouted state again
hostname | grep east > /dev/null && ipsec status | grep "[.][.][.]"
