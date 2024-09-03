/testing/guestbin/swan-prep --nokeys
cp policies/* /etc/ipsec.d/policies/
ipsec start
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 11,' -- ipsec auto --status
echo "initdone"
