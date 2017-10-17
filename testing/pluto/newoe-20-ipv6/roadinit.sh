/testing/guestbin/swan-prep --6
cp policies/* /etc/ipsec.d/policies/
echo "2001:db8:1:2::0/64" >>  /etc/ipsec.d/policies/private-or-clear
echo "2001:db8:1:3::254/128" >> /etc/ipsec.d/policies/clear
echo "2001:db8:1:2::254/128" >> /etc/ipsec.d/policies/clear
echo "fe80::/10" >> /etc/ipsec.d/policies/clear
ipsec start
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
ip -s xfrm monitor > /tmp/xfrm-monitor.out &
echo "initdone"
