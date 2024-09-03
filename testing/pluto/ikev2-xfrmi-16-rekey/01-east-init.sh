/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
../../guestbin/tcpdump.sh --start -i eth1
echo "initdone"
