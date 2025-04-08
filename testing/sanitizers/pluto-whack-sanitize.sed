#why filter? /^010 .* retransmission; will wait .*/d
#why filter? /discarding duplicate packet; already STATE_MAIN_I3/d
#why filter? /^002 .*received Vendor ID Payload/d

# IKEv1
/inbound IPsec SA installed/ s/ESP=>0x[a-f0-9]* <0x[a-f0-9]*/ESP=>0xESPESP <0xESPESP/
s/\(IPsec SA established .* mode\) \([^ ]*ESP[^>]*>\)0x[a-f0-9]* <0x[a-f0-9]* \(xfrm.[^ ]* IPCOMP.>0x\)[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1 \20xESPESP <0xESPESP \3ESPESP <0xESPESP \4/
s/\(IPsec SA established .* mode\) \([^ ]*ESP[^=]*=>\)0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1 \20xESPESP <0xESPESP \3/
s/\(IPsec SA established .* mode\) \([^ ]*AH[^ ]*\)0x[a-f0-9]* \(.*\)0x[a-f0-9]* \(.*\)$/\1 \20xAHAH \30xAHAH \4/

# IKEv2; need to handle {ESP,AH}/TCP
s/\(established Child SA.*[^A-Z]IPCOMP.\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xESPESP <0xESPESP \2/
s/\(established Child SA.*[^A-Z]ESP[^=]*=\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xESPESP <0xESPESP \2/
s/\(established Child SA.*[^A-Z]AH[^=]*=\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xAHAH <0xAHAH \2/

# IKEv2; need to handle {ESP,AH}/TCP
s/\(rekeyed Child SA.*[^A-Z]IPCOMP.\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xESPESP <0xESPESP \2/
s/\(rekeyed Child SA.*[^A-Z]ESP[^=]*=\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xESPESP <0xESPESP \2/
s/\(rekeyed Child SA.*[^A-Z]AH[^=]*=\)>0x[a-f0-9]* <0x[a-f0-9]* \(.*\)$/\1>0xAHAH <0xAHAH \2/

# Generated RSA keys have some fuzz
s/ \([0-9]\)[0-9][0-9][0-9]-bit RSA/ \1nnn-bit RSA/
s/ \([0-9]\)[0-9][0-9]-bit RSA/ \1nn-bit RSA/

/msgid[:=]00000000/! { s,msgid\([:=]\)[0-9a-z]*,msgid\1MSGID, ; }

s,; \([a-z0-9A-Z_]\+\) in [0-9]\+s,; \1 in XXs,g
s, remaining life [0-9][0-9\.]*s, remaining life XXs,

/WARNING: calc_dh_shared(): for OAKLEY_GROUP_MODP/d
s/add_time=[0-9]*,/add_time=1234567890,/
s/, age=[^,]*,/, age=XXX,/
s/SN: 0x[a-f0-9]*/SN: 0xXX/

# Hack: real fix is to cleanup the delete log line and use str_datetime()
s/ aged [0-9]*\.[0-9]*s / /

/ERROR: asynchronous network error report/d
