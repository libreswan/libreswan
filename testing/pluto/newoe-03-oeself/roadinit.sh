/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
../../guestbin/ip.sh address add 192.1.3.210/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
echo "initdone"
