/testing/guestbin/swan-prep
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/tcpdump.sh --start -i eth0
ipsec whack --impair revival
ipsec add road
echo "initdone"
