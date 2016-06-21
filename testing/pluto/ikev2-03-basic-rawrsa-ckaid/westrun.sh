/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# see description.txt
! ipsec auto --add westnet-eastnet-ikev2
ipsec auto --add westnet-eastnet-ipv4
ipsec auto --add westnet-eastnet-ikev2-ckaid
