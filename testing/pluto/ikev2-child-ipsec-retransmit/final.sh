# should show just EAST with SA
ipsec trafficstatus

# should show retransmits on east
grep '^[^|].* CREATE_CHILD_SA .* retransmit' /tmp/pluto.log
