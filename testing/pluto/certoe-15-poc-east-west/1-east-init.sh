/testing/guestbin/swan-prep  --x509
setenforce 0
ip route del default
ip route add default via 192.9.4.1
certutil -D -n west -d sql:/etc/ipsec.d
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
#echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
#echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/clear-or-private
#echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/private
echo "192.1.2.45/32"  >> /etc/ipsec.d/policies/private
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# give OE policies time to load
sleep 5
echo "initdone"
