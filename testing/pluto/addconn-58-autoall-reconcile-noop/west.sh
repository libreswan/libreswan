/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

ipsec delete corp/1x2
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u
