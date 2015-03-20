/^010 .* retransmission; will wait .*/d
/discarding duplicate packet; already STATE_MAIN_I3/d
/^002 .*received Vendor ID Payload/d
s/\(IPsec SA established .* mode\) {.*}/\1/
s/IPsec SA established {.*}/IPsec SA established/
s/\(PARENT SA established .* mode\) {.*}/\1/
s,\(instance with peer .*\) {isakmp=#.*/ipsec=#.*},\1,
s,\(initiating Quick Mode .*\) {using isakmp#.*},\1,
s,\(initiating Quick Mode .* to replace #.*\) {using isakmp#.*},\1,
s,{msgid.*},,
s,\( EVENT_SA_REPLACE in \)[0-9]\+s,\1 00s,g
s,\(003 .* received Vendor ID payload \[Libreswan \).*,\1,
/WARNING: calc_dh_shared(): for OAKLEY_GROUP_MODP/d
