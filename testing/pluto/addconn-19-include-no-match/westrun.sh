ipsec start
../../guestbin/wait-until-pluto-started

# what is being included
grep include /etc/ipsec.conf

# expect no complaints
ipsec auto --add west
