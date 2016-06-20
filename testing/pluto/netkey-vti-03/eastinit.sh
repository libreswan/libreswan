/testing/guestbin/swan-prep
ip addr add 10.0.2.254/24 dev eth0
ip addr add 192.1.2.24/24 dev eth1
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-01
ipsec auto --add westnet-eastnet-02
echo "initdone"
