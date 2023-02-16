# Import the old and new certificates

ipsec pk12util -i OUTPUT/new-west.p12 -W secret
ipsec pk12util -i OUTPUT/old-west.p12 -W secret

# now get going

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec auto --add old-west
ipsec auto --add new-west
