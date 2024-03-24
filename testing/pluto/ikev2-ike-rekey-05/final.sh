ipsec whack --trafficstatus
ipsec showstates
# there should be only one IKE_SA_INIT exchange
grep "sent IKE_SA_INIT" /tmp/pluto.log
