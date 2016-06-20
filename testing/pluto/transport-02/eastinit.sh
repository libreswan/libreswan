: ==== start ====
TESTNAME=transport-02
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west--east-port3
ipsec auto --add west--east-pass
ipsec auto --add west--east-pass2

sh /etc/init.d/inetd start

ipsec auto --route west--east-pass
ipsec auto --route west--east-pass2
ipsec eroute
ipsec whack --debug-control --debug-controlmore --debug-crypt
