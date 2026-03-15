/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec whack --impair block_inbound:yes
ipsec auto --add east-west

# Make sure WEST IKE SA nonce is lower than EAST's.
ipsec whack --impair ike_initiator_nonce:0x01

