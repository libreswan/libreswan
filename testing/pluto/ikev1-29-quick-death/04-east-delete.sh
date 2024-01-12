# to be sure; initiator's already received it
../../guestbin/wait-for.sh --match '#2: sent Quick' -- cat /tmp/pluto.log
ipsec unroute west-to-east
