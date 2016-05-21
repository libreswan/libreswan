/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
iptables -I INPUT -p udp -m length --length 0x5dc:0xffff -j LOGDROP
ipsec auto --add x509
echo done
