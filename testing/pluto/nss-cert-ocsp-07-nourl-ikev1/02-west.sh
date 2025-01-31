/testing/guestbin/swan-prep --x509 --revoked
ipsec certutil -D -n east
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair revival
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"
ipsec auto --up nss-cert-ocsp
echo done
