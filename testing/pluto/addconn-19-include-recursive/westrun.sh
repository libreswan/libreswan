ipsec start
../../guestbin/wait-until-pluto-started

# what is being included
grep include /etc/ipsec.conf

# expect the add to fail as recursive
ipsec auto --add west
