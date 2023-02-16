/testing/guestbin/swan-prep --x509
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
ipsec whack --impair suppress-retransmits
echo "initdone"
