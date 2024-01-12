/testing/guestbin/swan-prep --x509
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_pkcs7_thingie
ipsec auto --add westnet-eastnet-x509
ipsec whack --impair suppress_retransmits
echo "initdone"
