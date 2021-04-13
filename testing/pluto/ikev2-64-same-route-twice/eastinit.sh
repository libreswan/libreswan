# special test case remove easnet ip address
ip addr show dev eth0 | grep  192.0.2.254 && ip addr del 192.0.2.254/24 dev eth0
# add ip address of WESTNET
ip addr show dev eth0 | grep 192.0.1.254 || ip addr add 192.0.1.254/24 dev eth0
/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
