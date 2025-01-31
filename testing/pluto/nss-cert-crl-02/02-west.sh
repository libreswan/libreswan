/testing/guestbin/swan-prep --x509 --revoked
ipsec certutil -D -n east
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"
ipsec auto --up nss-cert-crl
echo done
