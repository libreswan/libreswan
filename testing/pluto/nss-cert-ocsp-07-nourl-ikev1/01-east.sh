/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# replace nic with the nic-no url cert
ipsec certutil -D -n nic
ipsec certutil -A -i /testing/x509/certs/nic-nourl.crt -n nic -t "P,,"
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec whack --impair timeout_on_retransmit
echo "initdone"
