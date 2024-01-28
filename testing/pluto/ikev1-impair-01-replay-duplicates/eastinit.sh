/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair duplicate_inbound
ipsec auto --add westnet-eastnet
echo "initdone"
