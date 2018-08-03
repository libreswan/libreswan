/testing/guestbin/swan-prep --x509
ipsec _stackmanager start
service auditd stop
rm  -f /var/log/audit/audit.log
systemctl start auditd.service
mkdir -p /var/run/pluto
ipsec pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"
