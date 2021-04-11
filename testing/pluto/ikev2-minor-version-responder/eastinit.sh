/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair minor-version-bump
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
