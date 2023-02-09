# Import the cert

pk12util -i OUTPUT/east.p12 -W secret -d /etc/ipsec.d

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add new-ca
ipsec auto --add old-ca
ipsec auto --add hog-ca
