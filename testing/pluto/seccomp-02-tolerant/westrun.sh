ipsec auto --up nss-cert
ipsec auto --down nss-cert
# pluto should survive this and report back
ipsec whack --seccomp-crashtest
# no log entries should appear
ausearch -r -m seccomp -ts boot
echo done
