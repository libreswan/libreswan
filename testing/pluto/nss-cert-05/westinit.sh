/testing/guestbin/swan-prep --x509 --signedbyother
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair delete-on-retransmit
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress-retransmits
echo "initdone"
