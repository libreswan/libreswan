: ==== start ====
TESTNAME=nat-transport-02
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd restart

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north--east-port3
ipsec whack --debug-control --debug-controlmore --debug-crypt

