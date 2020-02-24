#ESP(spi=0xfd9b5931,seq=0x1), length 288
s/spi=0x[0-9a-f]*\(,seq=0x1), length\) [0-9]*$/spi=0xSPISPI\1 XXX/
#next lines comes from console, only on kvm and not on namespace
/device eth[0-1] entered promiscuous mode/d
/tcpdump: listening on eth[0-1], link-type/d
