/testing/guestbin/swan-prep
ip addr add 10.0.2.254 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-01
ipsec auto --add westnet-eastnet-02
echo "initdone"
