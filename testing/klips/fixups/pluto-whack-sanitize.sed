#why filter? /^010 .* retransmission; will wait .*/d
#why filter? /discarding duplicate packet; already STATE_MAIN_I3/d
#why filter? /^002 .*received Vendor ID Payload/d
s/\(IPsec SA established .* mode\) \(.*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]*\(.*\)$/\1 \20xESPESP\30xESPESP\4/
s/\(PARENT SA established .* mode\) \(.*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]*\(.*\)$/\1 \20xESPESP\30xESPESP\4/
s,\(instance with peer .*\) {isakmp=#.*/ipsec=#.*},\1,
s,\(initiating Quick Mode .*\) {using isakmp#.*},\1,
s,\(initiating Quick Mode .* to replace #.*\) {using isakmp#.*},\1,
s,{msgid.*},,
s,\( EVENT_SA_REPLACE in \)[0-9]\+s,\1 00s,g
s,\(003 .* received Vendor ID payload \[Libreswan \).*,\1,
/WARNING: calc_dh_shared(): for OAKLEY_GROUP_MODP/d
