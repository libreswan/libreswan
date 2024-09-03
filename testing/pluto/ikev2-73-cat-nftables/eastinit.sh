/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
ipsec auto --add east-rw
../../guestbin/wait-for.sh --match 'loaded 1,' -- ipsec auto --status
echo "initdone"
