/testing/guestbin/swan-prep --x509 --signedbyother
ipsec certutil -D -n east
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
