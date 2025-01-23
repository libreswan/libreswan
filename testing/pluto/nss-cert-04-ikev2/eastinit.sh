/testing/guestbin/swan-prep --x509
ipsec start
# check
ipsec certutil -L

../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
