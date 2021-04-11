/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
ipsec whack --impair suppress-retransmits
echo "initdone"
