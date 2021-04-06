ipsec status |grep STATE_
# there should be only one IKE_INIT exchange
grep "STATE_PARENT_I1 with STF_OK" /tmp/pluto.log
grep "PARENT_R1 with status STF_OK" /tmp/pluto.log
