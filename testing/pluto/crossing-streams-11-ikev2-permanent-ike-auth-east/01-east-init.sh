/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --add east-west

# Make sure EAST IKE SA nonce is higher thant WEST's.
ipsec whack --impair ike_initiator_nonce:0xff
