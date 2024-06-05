/testing/guestbin/swan-prep --x509
../../guestbin/ip.sh address add 192.0.22.254/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnets
ipsec auto --status | grep northnet-eastnets
ipsec whack --impair suppress_retransmits
echo "initdone"
