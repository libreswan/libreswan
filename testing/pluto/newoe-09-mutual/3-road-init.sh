/testing/guestbin/swan-prep --nokeys
 echo 1 >/proc/sys/net/core/xfrm_acq_expires
cp policies/* /etc/ipsec.d/policies/
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 13' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
