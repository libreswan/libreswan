: ==== start ====

# ipsec setup stop; umount /usr/local; mount /usr/local
# iptables -F INPUT 
# iptables -F OUTPUT

TESTNAME=dpd-08
source /testing/pluto/bin/westlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east

