/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
# test config for syntax errors
ipsec addconn --checkconfig --config /etc/ipsec.conf
# start for test
ipsec start
../../guestbin/wait-until-pluto-started
# test secrets reading for early warning of syntax errors
ipsec secrets
../../guestbin/if-namespace.sh /usr/sbin/sshd -o PidFile=/var/run/pluto/sshd.pid
# ready for System Role to drop file(s) into /etc/ipsec.d/
echo "initdone"
