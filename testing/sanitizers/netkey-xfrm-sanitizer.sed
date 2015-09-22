# This depends on XFRM markers inserted by "ipsec look"
/^XFRM state:/,/XFRM done/s/spi 0x[^ ]* /spi 0xSPISPIXX /g
/^XFRM state:/,/XFRM done/s/auth\(.*\) 0x[^ ]* \(.*\)$/auth\1 0xHASHKEY \2/g
/^XFRM state:/,/XFRM done/s/enc \(.*\) 0x.*$/enc \1 0xENCKEY/g
/^XFRM state:/,/XFRM done/s/aead \(.*\) 0x[^ ]*\( .*\)$/aead \1 0xENCAUTHKEY\2/g
/^XFRM state:/,/XFRM done/s/reqid [0-9]* /reqid REQID /g
