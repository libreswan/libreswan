#!/usr/bin/perl

# when tcpdump'ing with 3.7, it attempts to decrypt the second SA, even
# though the key is wrong. A 3.8 of tcpdump may fix this.
#
# until then, just remove the extra junk at the end.
# 192.1.2.23 > 192.1.2.45: ESP(spi=0x12345678,seq=0x2): 192.1.2.23 > 192.0.1.1: ESP(spi=0xabcdabcd,seq=0x2):  ip-proto-241 75 (ipip-proto-4)
#
#
while(<>) {

#  ,seq=0x2): 192.1.2.23 > 192.0.1.1: ESP(spi=0xabcdabcd,seq=0x2):  ip-proto-241 75 (ipip-proto-4)
	#s/(.* ESP\(spi=0xabcdabcd,seq=.*\)).*$/\1/;
	s/(.* ESP\(spi=0xabcdabcd,seq=0x[0-9a-fA-F]+\)).*$/\1/;
	print;
}

