/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
# replace nic with the nic-no url cert
certutil -d sql:/etc/ipsec.d -D -n nic
certutil -A -i /testing/x509/certs/nic-nourl.crt -d sql:/etc/ipsec.d -n nic -t "P,,"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec whack --impair delete-on-retransmit
echo "initdone"
