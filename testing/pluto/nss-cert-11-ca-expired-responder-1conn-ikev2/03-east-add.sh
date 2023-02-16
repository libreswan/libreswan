# Import the cert

ipsec pk12util -i OUTPUT/east.p12 -W secret

# now get going

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
