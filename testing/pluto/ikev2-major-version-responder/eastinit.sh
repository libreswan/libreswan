/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair major_version_bump
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
