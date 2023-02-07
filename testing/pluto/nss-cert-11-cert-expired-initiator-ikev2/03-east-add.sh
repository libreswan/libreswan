# Import the cert

pk12util -i OUTPUT/east.p12 -W secret -d /etc/ipsec.d

# now get going

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
