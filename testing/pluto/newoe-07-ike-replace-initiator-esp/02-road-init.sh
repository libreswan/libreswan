/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
ipsec start

../../guestbin/wait-until-pluto-started

# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 11,' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
