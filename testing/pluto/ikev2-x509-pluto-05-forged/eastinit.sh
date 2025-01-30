/testing/guestbin/swan-prep --nokeys
# no CA, no west, ...
/testing/x509/import.sh real/mainca/east.end.p12
# ... instead, fake west
ipsec certutil -A -n west -i west-alt.crt -t P,,
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
echo "initdone"
