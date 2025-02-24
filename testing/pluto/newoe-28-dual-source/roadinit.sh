/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-2
ip addr add 192.1.3.208/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load and route
sleep 5
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
