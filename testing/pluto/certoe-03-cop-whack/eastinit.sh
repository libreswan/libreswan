/testing/guestbin/swan-prep  --x509
certutil -D -n road -d sql:/etc/ipsec.d
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair retransmits
# give OE policies time to load
sleep 5
echo "initdone"
