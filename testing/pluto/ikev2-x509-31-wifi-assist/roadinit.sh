/testing/guestbin/swan-prep --x509
ip addr add 192.1.3.210/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add rw-lte
ipsec auto --add rw-wifi
echo "initdone"
