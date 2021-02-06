/IMPAIR:/ p

# mark start of some packets
/parse ISAKMP Message:/,/length:/ {
	/next payload type: ISAKMP_NEXT_D/ {
		i\
-- start message (D)
       	     p
	}
	/next payload type: ISAKMP_NEXT_HASH/ {
		i\
-- start message (HASH)
       	     p
	}
	/next payload type: ISAKMP_NEXT_ID/ {
		i\
-- start message (ID)
       	     p
	}
}

# payloads that need authentication

/parse ISAKMP Delete Payload:/,/number of SPIs/ p
/parse ISAKMP Hash Payload:/,/length:/ p
/parse ISAKMP Signature Payload:/,/length:/ p

# authentication message

# G;p appends the empty-hold-space + NL to pattern space; and then
# prints it

/^[^|].* authenticated using RSA/ {G;p}
/received .* message HASH[^ ]* data / {G;p}
/received .* message SIG[^ ]* data / {G;p}
/^[^|].* message for STATE_INFO_PROTECTED is missing payloads HASH/ {G;p}
/received Hash Payload does not match computed value/ {G;p}
/Informational Exchange is for an unknown/ {
	s/MSGID:0x.*/MSGID:0x..../
	G
	p
}
