/testing/guestbin/swan-prep --x509 --x509name ../otherca/signedbyother
ipsec certutil -M -n 'Libreswan test CA for otherca - Libreswan' -t 'CT,,'
ipsec certutil -D -n east
ipsec certutil -D -n east-ec
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair delete-on-retransmit
ipsec auto --add westnet-eastnet-x509-cr
echo "initdone"
