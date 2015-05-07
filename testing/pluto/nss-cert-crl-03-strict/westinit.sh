/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n east
# confirm that the network is alive
ping -n -c2 -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
ipsec setup start
# confirm with a ping
ping -n -c2 -I 192.0.1.254 192.0.2.254
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"
