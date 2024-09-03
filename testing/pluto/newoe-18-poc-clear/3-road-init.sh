/testing/guestbin/swan-prep --nokeys
echo 3 >/proc/sys/net/core/xfrm_acq_expires
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
