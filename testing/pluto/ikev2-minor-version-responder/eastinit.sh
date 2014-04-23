/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start:
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-minor-version-bump
ipsec auto --add westnet-eastnet-ikev2
: ==== cut ====
ipsec auto --status
: ==== tuc ====
echo "initdone"
