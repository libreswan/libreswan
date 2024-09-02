/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-aes256
ipsec auto --status | grep westnet-eastnet-aes256
echo "initdone"
