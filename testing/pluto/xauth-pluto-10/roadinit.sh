/testing/guestbin/swan-prep
ip addr add 192.1.3.194/24 dev eth0
ip route add default via 192.1.3.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth-road-eastnet
echo done
