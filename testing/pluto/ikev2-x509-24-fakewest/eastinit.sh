/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -i /testing/x509/real/mainca/east.end.p12
ipsec certutil -A -t P,,, -n west -i /testing/x509/real/mainca/west.end.cert
# this leaves real east and real west certs. other end will use
# different fake west cert
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
