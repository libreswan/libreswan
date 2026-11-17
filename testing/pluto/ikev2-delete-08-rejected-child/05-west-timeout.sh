ipsec down rejected-child
# Inbound messages 1-3 are IKE_SA_INIT, IKE_AUTH, and Child Delete; 4 is IKE Delete.
ipsec whack --impair suppress_retransmits
ipsec whack --impair drop_inbound:7
ipsec up rejected-child
ipsec showstates
ipsec _kernel state
echo done
