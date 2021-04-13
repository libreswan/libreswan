/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n "Libreswan test CA for mainca - Libreswan"
certutil -d sql:/etc/ipsec.d -D -n "west"
certutil -d sql:/etc/ipsec.d -A -n west -i west-alt.crt -t P,,
certutil -d sql:/etc/ipsec.d -L
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
echo "initdone"
