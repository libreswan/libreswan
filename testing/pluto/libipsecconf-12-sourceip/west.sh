/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# fails because there's no subnet=
ipsec auto --add sourceip-without-selector
ipsec auto --add sourceips-without-selector

# fails because sourceip is not within subnet
ipsec auto --add sourceip-outside-selector

# fails because sourceip is not within subnet
ipsec auto --add sourceips-outside-selectors

# all good
ipsec auto --add sourceip-inside-selector
ipsec auto --add sourceips-inside-selectors

# subnets= tests can't check inside/outside
ipsec auto --add sourceip-outside-subnets
ipsec auto --add sourceip-inside-subnets
ipsec auto --add sourceips-inside-subnets

ipsec whack --status
