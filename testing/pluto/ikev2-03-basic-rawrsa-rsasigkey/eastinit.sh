/testing/guestbin/swan-prep
: > /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-rsasigkey-east-rsasigkey
ipsec auto --status
echo "initdone"
