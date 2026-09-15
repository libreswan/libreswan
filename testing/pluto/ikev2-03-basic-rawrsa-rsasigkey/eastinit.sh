/testing/guestbin/swan-prep --hostkeys
: > /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-rsasigkey-east-rsasigkey
ipsec status
echo "initdone"
