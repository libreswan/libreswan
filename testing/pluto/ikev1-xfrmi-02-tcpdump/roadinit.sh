/testing/guestbin/swan-prep
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road
../../guestbin/tcpdump.sh --start -i eth0
echo "initdone"
