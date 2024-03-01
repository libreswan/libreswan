
#
# east receives but blocks IKE_SA_INIT request
#
# east restarts leaving west in limbo
# east initiates

ipsec whack --shutdown --leave-state

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits

ipsec add east-west
ipsec up east-west --asynchronous
