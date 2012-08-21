: ==== start ====

TESTNAME=dpd-08

source /testing/pluto/bin/eastlocal.sh

ipsec setup start

ipsec auto --add west-east

/usr/sbin/sshd

