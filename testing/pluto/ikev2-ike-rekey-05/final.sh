ipsec whack --trafficstatus
ipsec showstates
# there should be only one IKE_SA_INIT exchange
grep "PARENT_[IR]1 with status STF_OK" /tmp/pluto.log
