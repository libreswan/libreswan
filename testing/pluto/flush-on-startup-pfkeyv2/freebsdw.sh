../../guestbin/prep.sh
ipsec initnss

# add a policy + state
setkey -f setkey.in

ipsec _kernel state
ipsec _kernel policy

# start pluto
ipsec pluto --config /usr/local/etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started

# check policy/state gone
ipsec _kernel state
ipsec _kernel policy
