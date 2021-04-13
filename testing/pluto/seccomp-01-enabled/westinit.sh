/testing/guestbin/swan-prep --x509
ipsec _stackmanager start
service auditd stop > /dev/null 2> /dev/null
rm  -f /var/log/audit/audit.log
systemctl start auditd.service
mkdir -p /var/run/pluto
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
