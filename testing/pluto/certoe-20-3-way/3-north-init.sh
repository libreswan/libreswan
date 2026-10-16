/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/north.p12
cp ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.209/32" >> /etc/ipsec.d/policies/clear-or-private
echo "192.1.2.45/32" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec status
echo "initdone"
