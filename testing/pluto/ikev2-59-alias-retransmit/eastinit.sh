/testing/guestbin/swan-prep
ip addr show dev eth0 | grep 192.0.22.251 || (ip addr add 192.0.22.251/24 dev eth0)
ip addr show dev eth0 | grep 192.0.22.254 || (ip addr add 192.0.22.254/24 dev eth0)
ip addr show dev eth0 | grep 192.0.2.251 || (ip addr add 192.0.2.251/24 dev eth0)
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec status | grep north-eastnets
echo "initdone"
