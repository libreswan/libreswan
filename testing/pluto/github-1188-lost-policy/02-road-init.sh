/testing/guestbin/swan-prep
echo "192.1.2.0/24"  > /etc/ipsec.d/policies/private
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
