/testing/guestbin/swan-prep
echo "192.1.3.0/24"  > /etc/ipsec.d/policies/private
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
