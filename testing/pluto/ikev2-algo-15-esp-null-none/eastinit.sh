/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair allow-null-none
ipsec auto --add esp=null-none
ipsec auto --status | grep esp=null-none
echo "initdone"
