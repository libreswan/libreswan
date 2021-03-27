/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
../../pluto/bin/wait-for.sh --match 'loaded 13' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out &
echo "initdone"
