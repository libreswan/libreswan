# now restart
ipsec whack --shutdown --leave-state
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-to-east
ipsec up west-to-east
