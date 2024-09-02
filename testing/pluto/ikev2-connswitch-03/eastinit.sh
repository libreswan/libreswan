/testing/guestbin/swan-prep --hostkeys
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-one
ipsec auto --add westnet-eastnet-two
ipsec auto --add westnet-eastnet-three
echo "initdone"
