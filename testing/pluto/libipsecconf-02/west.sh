/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# These should load
ipsec auto --add base
ipsec auto --add subnet4
ipsec auto --add subnet6-good

# this one should fail to load
ipsec auto --add subnet6-bad

