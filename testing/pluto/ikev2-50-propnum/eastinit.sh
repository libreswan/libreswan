../../guestbin/swan-prep
ipsec start
../../pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-propnum
ipsec whack --impair suppress-retransmits
echo "initdone"
