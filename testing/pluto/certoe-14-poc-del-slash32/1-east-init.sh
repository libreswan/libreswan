/testing/guestbin/swan-prep  --x509
ip route del default
ip route add default via 192.9.2.254
ip route add 192.1.3.0/24 via 192.1.2.254
certutil -D -n road -d sql:/etc/ipsec.d
certutil -D -n east -d sql:/etc/ipsec.d
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/private
restorecon -R /etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# give OE policies time to load
sleep 5
echo "initdone"
