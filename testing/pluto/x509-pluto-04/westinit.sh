/testing/guestbin/swan-prep --x509 --x509name ../otherca/signedbyother
certutil -M -n 'Libreswan test CA for otherca - Libreswan' -d sql:/etc/ipsec.d/ -t 'CT,,'
certutil -D -n east -d sql:/etc/ipsec.d
certutil -D -n east-ec -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair delete-on-retransmit
ipsec auto --add westnet-eastnet-x509-cr
echo "initdone"
