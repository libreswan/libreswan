/testing/guestbin/swan-prep --x509
ip addr add 192.0.20.254/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
