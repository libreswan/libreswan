/testing/guestbin/swan-prep --nokeys
# added different CA

/testing/x509/import.sh real/otherca/otherwest.all.p12
# check
ipsec certutil -L

cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
