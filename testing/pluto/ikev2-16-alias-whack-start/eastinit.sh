/testing/guestbin/swan-prep --x509
ip addr show dev eth0 | grep 192.0.22.254 || (ip addr add 192.0.22.254/24 dev eth0)
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnets
ipsec auto --status | grep northnet-eastnets
ipsec whack --impair suppress-retransmits
echo "initdone"
