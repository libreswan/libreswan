/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-null
ipsec auto --add westnet-eastnet-esp-null
ipsec auto --status | grep westnet-eastnet-esp-null
echo "initdone"
