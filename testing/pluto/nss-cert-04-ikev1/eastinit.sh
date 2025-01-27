/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/east.all.p12
ipsec certutil -M -n mainca -t CT,,
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
