/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 13' -- ipsec auto --status
echo "initdone"
