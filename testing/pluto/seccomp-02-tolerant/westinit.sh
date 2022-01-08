/testing/guestbin/swan-prep --x509
# why start pluto directly?
mkdir -p /var/run/pluto
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
