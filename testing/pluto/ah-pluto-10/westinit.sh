/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair retransmits
ipsec auto --add westnet-eastnet-ah
echo "initdone"
