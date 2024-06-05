/testing/guestbin/swan-prep  --x509
../../guestbin/ip.sh route del default
../../guestbin/ip.sh route add default via 192.9.2.1
ipsec certutil -D -n west
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.45/32"  >> /etc/ipsec.d/policies/private
restorecon -R /etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
