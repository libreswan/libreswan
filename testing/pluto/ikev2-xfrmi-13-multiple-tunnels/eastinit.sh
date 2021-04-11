/testing/guestbin/swan-prep
ip addr add 192.0.21.254/24 dev eth0 2>/dev/null
ip addr add 192.0.22.254/24 dev eth0 2>/dev/null
ip addr add 192.0.23.254/24 dev eth0 2>/dev/null
ip addr add 192.0.24.254/24 dev eth0 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-21
ipsec auto --add north-east-22
ipsec auto --add north-east-23
ipsec auto --add north-east-24
echo "initdone"
