/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet
ip tunnel add ipsec0 mode vti local 192.1.2.23 key 20
ip link set ipsec0 up
sysctl -w net.ipv4.conf.ipsec0.disable_policy=1
sysctl -w net.ipv4.conf.ipsec0.rp_filter=0
sysctl -w net.ipv4.conf.ipsec0.forwarding=1
# east would need to add a route into the vti device in updown
echo "initdone"
