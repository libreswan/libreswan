/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair duplicate_inbound
ipsec add westnet-eastnet
echo "initdone"
