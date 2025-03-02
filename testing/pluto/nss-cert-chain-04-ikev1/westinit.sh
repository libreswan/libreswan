/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west_chain_endcert.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-chain-B
ipsec auto --status |grep road-chain-B
ipsec certutil -L
ipsec whack --impair suppress_retransmits
echo "initdone"
