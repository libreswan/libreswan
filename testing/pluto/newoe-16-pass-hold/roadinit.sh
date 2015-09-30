/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# ensure for tests acquires expire before our failureshunt is installed
echo 30 > /proc/sys/net/core/xfrm_acq_expires
# give OE policies time to load
sleep 5
# temp workaround for outgoing packet matching packetdefault instead of private-or-clear
ipsec auto --delete packetdefault
ip -s xfrm monitor > /tmp/xfrm-monitor.out &
echo "initdone"
