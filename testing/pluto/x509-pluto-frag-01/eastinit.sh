/testing/guestbin/swan-prep --x509
iptables -I INPUT -p udp -m length --length 0x5dc:0xffff -j LOGDROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add x509
ipsec whack --impair suppress-retransmits
echo "initdone"
