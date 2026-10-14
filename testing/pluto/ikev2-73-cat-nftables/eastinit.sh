/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
ipsec add east-rw
../../guestbin/wait-for.sh --match 'loaded 1,' -- ipsec status
echo "initdone"
