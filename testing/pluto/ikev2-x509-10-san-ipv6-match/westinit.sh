/testing/guestbin/swan-prep --x509 --46
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add san
ipsec listpubkeys
ipsec certutil -L west -n west | grep 'IP Address:'
echo "initdone"
