/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

ipsec add --autoall

../../guestbin/ip.sh address add 192.1.2.99/24 dev eth1
../../guestbin/ip-route.sh replace 192.1.2.0/24 dev eth1 src 192.1.2.99

# only the conn using %defaultroute is rebuilt
ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u
