: ==== start ====

# ipsec setup stop; umount /usr/local; mount /usr/local
# iptables -F INPUT 
# iptables -F OUTPUT

TESTNAME=dpd-07
source /testing/pluto/bin/westlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

sleep 5
ipsec auto --add west-east

