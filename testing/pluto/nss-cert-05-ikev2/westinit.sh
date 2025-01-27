/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/west.all.p12
ipsec certutil -M -n mainca -t CT,,
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/otherwest.all.p12
ipsec certutil -M -n otherca -t CT,,
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
