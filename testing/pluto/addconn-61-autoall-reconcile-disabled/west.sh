/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort

ipsec add --autoall --config /testing/pluto/addconn-61-autoall-reconcile-disabled/west-reduced.conf
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
