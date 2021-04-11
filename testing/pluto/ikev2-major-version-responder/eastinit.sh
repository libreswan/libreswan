/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair major-version-bump
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
