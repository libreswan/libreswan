/testing/guestbin/swan-prep
ifconfig eth0 0.0.0.0 down
ifconfig eth1 178.62.253.21 netmask 255.255.192.0
ifconfig eth1:1 10.8.0.1 netmask 255.255.255.0
ifconfig eth1:2 10.9.0.1 netmask 255.255.255.0
route add default gw 178.62.192.1
# add many routes
sh ./ips.sh
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec addconn --verbose test
echo "initdone"
