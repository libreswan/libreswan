/testing/guestbin/swan-prep --x509
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j LOGDROP
# confirm clear text does not get through
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec whack --impair suppress-retransmits
echo "initdone"
