/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort

ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):   conn serial: \([^;]*\);.*/\1 \2/p' | sort
