/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "0.0.0.0/0"  >> /etc/ipsec.d/policies/block
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
