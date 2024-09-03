/testing/guestbin/swan-prep --nokeys
../../guestbin/ip.sh address add 192.1.3.210/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
