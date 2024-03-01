
#
# set up west
#

/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec whack --impair block_inbound:yes
ipsec add east-west
ipsec route east-west
