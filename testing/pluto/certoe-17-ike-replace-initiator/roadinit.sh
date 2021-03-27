/testing/guestbin/swan-prep --x509
cp policies/* /etc/ipsec.d/policies/
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 8' -- ipsec auto --status
echo "initdone"
