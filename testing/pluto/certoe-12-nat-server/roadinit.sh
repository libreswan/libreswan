/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
ipsec certutil -D -n road
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.128/27"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10' -- ipsec auto --status
echo "initdone"
