# Import the old and new certificates

pk12util -i OUTPUT/new-west.p12 -W secret -d /etc/ipsec.d
pk12util -i OUTPUT/old-west.p12 -W secret -d /etc/ipsec.d

# now get going

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec auto --add old-west
ipsec auto --add new-west
