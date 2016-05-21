/testing/guestbin/swan-prep --x509
cp /testing/x509/crls/cacrlvalid.crl /etc/ipsec.d/crls
certutil -D -n west -d sql:/etc/ipsec.d
iptables -A INPUT -i eth1 -s 192.0.1.0/24 -d 0.0.0.0/0 -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
