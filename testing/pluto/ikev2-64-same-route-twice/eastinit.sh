# special test case remove easnet ip address
../../guestbin/ip.sh address show dev eth0 | grep  192.0.2.254 && ../../guestbin/ip.sh address del 192.0.2.254/24 dev eth0
# add ip address of WESTNET
../../guestbin/ip.sh address show dev eth0 | grep 192.0.1.254 || ../../guestbin/ip.sh address add 192.0.1.254/24 dev eth0
/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east
echo "initdone"
