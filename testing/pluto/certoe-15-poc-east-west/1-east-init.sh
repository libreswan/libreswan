/testing/guestbin/swan-prep  --x509
ip route del default
ip route add default via 192.9.2.1
certutil -D -n west -d sql:/etc/ipsec.d
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.45/32"  >> /etc/ipsec.d/policies/private
restorecon -R /etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# give OE policies time to load
sleep 5
echo "initdone"
