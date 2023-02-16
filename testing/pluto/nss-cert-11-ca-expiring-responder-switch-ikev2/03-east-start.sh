# Import the cert

ipsec pk12util -i OUTPUT/east.p12 -W secret

ipsec start
../../guestbin/wait-until-pluto-started
