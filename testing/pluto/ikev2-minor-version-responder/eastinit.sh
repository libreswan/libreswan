/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-minor-version-bump
ipsec auto --add westnet-eastnet-ikev2
: ==== cut ====
ipsec auto --status
: ==== tuc ====
echo "initdone"
