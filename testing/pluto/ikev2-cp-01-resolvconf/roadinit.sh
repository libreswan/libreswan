/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add eastnet-any
# confirm we have stock resolv.conf
cat /etc/resolv.conf
echo initdone
