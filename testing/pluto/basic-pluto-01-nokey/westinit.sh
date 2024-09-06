/testing/guestbin/swan-prep
# there are no keys, but spell it out
rm -f /etc/ipsec.d/*db
ipsec initnss > /dev/null 2> /dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec auto --add westnet-eastnet
echo "initdone"
