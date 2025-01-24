/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/west.all.p12
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/otherwest.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add main
ipsec auto --add other
echo "initdone"
