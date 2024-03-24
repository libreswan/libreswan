ipsec showstates
# there should be only one IKE_INIT exchange
grep "sent IKE_SA_INIT" /tmp/pluto.log
