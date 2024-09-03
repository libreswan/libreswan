/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "0.0.0.0/0"  >> /etc/ipsec.d/policies/block
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
