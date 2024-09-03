/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
../../guestbin/ping-once.sh --up -I 192.1.3.209 7.7.7.7
ipsec start
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
