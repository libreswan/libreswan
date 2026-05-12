/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

ipsec add --autoall --config /testing/pluto/addconn-55-autoall-sweep/west-reduced.conf
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u
