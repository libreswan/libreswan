/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
ipsec start
../../guestbin/wait-until-pluto-started
iptables -I INPUT -p udp -m length --length 0x5dc:0xffff -j DROP
ipsec auto --add x509
echo done
