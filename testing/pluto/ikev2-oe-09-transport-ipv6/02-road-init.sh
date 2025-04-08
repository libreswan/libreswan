/testing/guestbin/swan-prep --46
cp policies/* /etc/ipsec.d/policies/
echo "2001:db8:1:2::0/64" >>  /etc/ipsec.d/policies/private-or-clear
echo "2001:db8:1:3::254/128" >> /etc/ipsec.d/policies/clear
echo "2001:db8:1:2::254/128" >> /etc/ipsec.d/policies/clear
echo "fe80::/10" >> /etc/ipsec.d/policies/clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 9' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
