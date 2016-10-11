ipsec auto --up nss-cert
ipsec auto --down nss-cert
# pluto should survive this and report back
ipsec whack --seccomp-crashtest
# no log entries should appear
grep SECCOMP /var/log/audit/audit.log
echo done
