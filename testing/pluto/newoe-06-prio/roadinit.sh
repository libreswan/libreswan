/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
ip -s xfrm monitor > /tmp/xfrm-monitor.out &
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
ipsec auto --add road-east-ikev2
echo "initdone"
