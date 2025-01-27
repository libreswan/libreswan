/testing/guestbin/swan-prep --nokeys

ipsec certutil -A -n east -t ,, -i /testing/x509/real/mainca/east.all.cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/otherwest.all.p12
ipsec certutil -M -n otherca -t 'CT,,'
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add westnet-eastnet-x509-cr
echo "initdone"
