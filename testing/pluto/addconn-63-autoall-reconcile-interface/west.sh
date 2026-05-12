/testing/guestbin/swan-prep
# a private interface, so the test network is left alone
../../guestbin/ip.sh link add dummy0 type dummy
../../guestbin/ip.sh address add 10.99.0.1/24 dev dummy0
../../guestbin/ip.sh link set dummy0 up
ipsec start
../../guestbin/wait-until-pluto-started
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u

# the interface still has the same address; both conns are left alone
ipsec add --autoall

# move the interface to a different address; delete before adding, a
# second address in the same subnet would only be a secondary
../../guestbin/ip.sh address del 10.99.0.1/24 dev dummy0
../../guestbin/ip.sh address add 10.99.0.2/24 dev dummy0

# only the conn using the interface is rebuilt
ipsec add --autoall
ipsec connectionstatus | sed -n -e 's/^\("[^"]*"\):.*/\1/p' | sort -u
