ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2,' -- ipsec auto --status

# initiate a reverse connection
../../guestbin/ping-once.sh --forget -I 192.1.2.23 192.1.3.209
../../guestbin/wait-for.sh --match private -- ipsec trafficstatus

# check the policy
ipsec _kernel policy
