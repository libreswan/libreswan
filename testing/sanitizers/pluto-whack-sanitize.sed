#why filter? /^010 .* retransmission; will wait .*/d
#why filter? /discarding duplicate packet; already STATE_MAIN_I3/d
#why filter? /^002 .*received Vendor ID Payload/d
s/\(IPsec SA established .* mode\) \([^ ]*ESP[^>]*>\)0x[a-f0-9]* <0x[a-f0-9]* \(xfrm.[^ ]* IPCOMP.>0x\)[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1 \20xESPESP <0xESPESP \3ESPESP <0xESPESP \4/
s/\(IPsec SA established .* mode\) \([^ ]*ESP[^=]*=>\)0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1 \20xESPESP <0xESPESP \3/
s/\(PARENT SA established .* mode\) \([^ ]ESP[^ ]*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]* \(.*\)$/\1 \20xESPESP\30xESPESP \4/
s/\(IPsec SA established .* mode\) \([^ ]*AH[^ ]*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]* \(.*\)$/\1 \20xAHAH \30xAHAH \4/
s/\(PARENT SA established .* mode\) \([^ ]*AH[^ ]*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]* \(.*\)$/\1 \20xAHAH\30xAHAH \4/
s,\(instance with peer .*\) {isakmp=#.*/ipsec=#.*},\1,
s,\(initiating Quick Mode .*\) {using isakmp#.*},\1,
s,\(initiating Quick Mode .* to replace #.*\) {using isakmp#.*},\1,
s,{msgid.*},,

s,\( EVENT_[a-z0-9A-Z_]\+ in \)[0-9]\+s,\1XXs,g
s, remaining life [0-9][0-9\.]*s, remaining life XXs,

s,\(003 .* received Vendor ID payload \[Libreswan \).*,\1,
/WARNING: calc_dh_shared(): for OAKLEY_GROUP_MODP/d
s/add_time=[0-9]*,/add_time=1234567890,/
s/SN: 0x[a-f0-9]*/SN: 0xXX/

s/start processing duplicate packet ([0-9]* bytes)/start processing duplicate packet (xxx bytes)/

# Hack: real fix is to cleanup the delete log line and use str_datetime()
s/ aged [0-9]*\.[0-9]*s / /

# Suppress actual state number; if things get re-numbered this needs
# to get updated.

s/^1[0-4][0-9] /1v1 /
s/^1[5-9][0-9] /1v2 /
