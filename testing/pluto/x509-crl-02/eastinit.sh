/testing/guestbin/swan-prep --x509
echo "192.9.4.245 nic.testing.libreswan.org" >> /etc/hosts
#cp /testing/x509/crls/cacrlnotyetvalid.pem /etc/ipsec.d/crls
certutil -D -n west -d sql:/etc/ipsec.d
iptables -A INPUT -i eth1 -s 192.0.1.0/24 -d 0.0.0.0/0 -j DROP
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
