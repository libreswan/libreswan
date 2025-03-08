/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.all.p12

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev1
ipsec auto --status | grep westnet-eastnet-ikev1
ipsec whack --impair suppress_retransmits
echo "initdone"
