/testing/guestbin/swan-prep --nokeys

# east and a root cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/east.all.p12
ipsec certutil -M -n mainca -t 'CT,,'
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"
