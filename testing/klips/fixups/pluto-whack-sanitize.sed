/^010 .* retransmission; will wait .*/d
/discarding duplicate packet; already STATE_MAIN_I3/d
/^002 .*received Vendor ID Payload/d
s/IPsec SA established {.*}/IPsec SA established/
s,\(instance with peer .*\) {isakmp=#.*/ipsec=#.*},\1,
s,\(initiating Quick Mode .*\) {using isakmp#.*},\1,
s,\(initiating Quick Mode .* to replace #.*\) {using isakmp#.*},\1,
s,{msgid.*},,
s,\(003 .* received Vendor ID payload \[Openswan \).*,\1,

