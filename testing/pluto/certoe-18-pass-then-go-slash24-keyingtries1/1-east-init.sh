/testing/guestbin/swan-prep  --x509
ipsec certutil -D -n road
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private-or-clear
# don't start ipsec yet
echo "initdone"
