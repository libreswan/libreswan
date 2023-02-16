# Import the cert

ipsec pk12util -i OUTPUT/east.p12 -W secret

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add new-ca
ipsec auto --add old-ca
ipsec auto --add hog-ca
