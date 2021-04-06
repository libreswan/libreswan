# should see #2 and #3 on east 
# only #2 on the road
ipsec trafficstatus
# should not find a match
grep "Notify Message Type: v2N_TS_UNACCEPTABLE" /tmp/pluto.log
# road fail to rekey and no clear log message to grep
