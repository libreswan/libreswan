/testing/guestbin/swan-prep --nokeys
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add road
ipsec auto --route road
echo "initdone"
