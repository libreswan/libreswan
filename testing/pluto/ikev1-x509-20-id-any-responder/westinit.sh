/testing/guestbin/swan-prep --x509 --x509name west-nosan
certutil -D -n east -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec status | grep idtype
#ipsec whack --impair suppress-retransmits
echo "initdone"
