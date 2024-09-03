/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo 192.1.3.0/24 >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
