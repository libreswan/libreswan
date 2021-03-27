/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
ip addr add 192.1.3.210/24 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
echo "initdone"
