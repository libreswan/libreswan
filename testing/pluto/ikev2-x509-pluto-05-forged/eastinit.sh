/testing/guestbin/swan-prep --x509
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
ipsec certutil -D -n "west"
ipsec certutil -A -n west -i west-alt.crt -t P,,
ipsec certutil -L
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
echo "initdone"
