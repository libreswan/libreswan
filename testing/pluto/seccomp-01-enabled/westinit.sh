/testing/guestbin/swan-prep --x509
# why manually start?
mkdir -p /var/run/pluto
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
