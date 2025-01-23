/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west 
# check
ipsec certutil -L

cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/clear-or-private
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
