s/_\([0-9a-f]*\)_p_msg_digest/_POINTER_p_msg_digest/g
s/_\([0-9a-f]*\)_p_state/_POINTER_p_state/g
s/_\([0-9a-f]*\)_p_connection/_POINTER_p_connection/g
s/_\([0-9a-f]*\)_p_unsigned_char/_POINTER_p_unsigned_char/g
s/ shared-secret  .. .. .. ..  .. .. .. ..  .. .. .. ..  .. .. .. ../: shared-secret  aa bb cc dd  aa bb cc dd  aa bb cc dd  aa bb cc dd/
s/^| outspi: 0x........ .*/: outspi: 0xOUTSOUTS DATA/
s/^| inspi: 0x........ .*/:  inspi: 0xININININ DATA/
s/^pb \([0-9]*\): .*/: pb \1: DATA/
s/^newpb \([0-9]*\): .*/: newpb \1: DATA/
s/^| \(t04a st:[0-9]*\)  .. .. .. .. .*/: \1 DATA/
/^| .*/d
s/\("west--east-psk" #.: next payload type of ISAKMP Identification Payload has an unknown value:\) .*/\1 VALUE/
/Pluto initialized/d
s/"west--east-psk" \(#.\): byte 2 of ISAKMP Identification Payload must be zero, but is not/"west--east-psk" \1: next payload type of ISAKMP Identification Payload has an unknown value: VALUE/
/packet from 192.1.2.23:500: Informational Exchange is for an unknown (expired?) SA/d


