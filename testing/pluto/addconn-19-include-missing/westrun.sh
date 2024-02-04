ipsec start
../../guestbin/wait-until-pluto-started

# what is being included
grep include /etc/ipsec.conf

# expect include file not found
ipsec auto --add west
