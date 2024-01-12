# should be rejected by the parser (requires allow-null-none)
! ipsec auto --add esp=null-none

# get esp=null-none past the parser
ipsec whack --impair allow_null_none

# include INTEG=NONE in the proposal
ipsec whack --impair v2_proposal_integ:allow-none
../../guestbin/libreswan-up-down.sh esp=null-none -I 192.0.1.254 192.0.2.254

# exclude INTEG=NONE in the proposal
ipsec whack --impair v2_proposal_integ:drop-none
../../guestbin/libreswan-up-down.sh esp=null-none -I 192.0.1.254 192.0.2.254

echo done
