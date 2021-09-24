ipsec whack --trafficstatus
ipsec status |grep STATE_
# there should be only one IKE_SA_INIT exchange
grep "PARENT_[IR]1 with status STF_OK" /tmp/pluto.log
