/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh west-east westnet-eastnet
echo "initdone"
