/testing/guestbin/swan-prep
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --add road
echo "initdone"
