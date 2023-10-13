# old unused rules commented out
#s/icmp\([0-9 ]*\):/icmp:/
#s/\(.*\)echo request seq .*\(.*\)/\1echo request (DF)\2/
#s/\(.*\)echo request, id .*, seq .*\(.*\)/\1echo request (DF)\2/
#s/\(.*\)echo reply, id .*, seq .*\(.*\)/\1echo reply (DF)\2/
#s/\.isakmp/.500/g
#s/^IP //
#s/: IP /: /
#s/icmp:/ICMP/g
#s/icmp \d:/ICMP/g
#s/, length \d//g
#s/echo reply seq .*/echo reply (DF)/

# reading from file /tmp/east.ikev2-xfrmi-02-responder.tcpdump.pcap, link-type EN10MB (Ethernet), snapshot length 262144
/reading from file .*tcpdump.pcap/ s/, snapshot length [0-9]*$//

# nflog
# 15:49:06.782887 IP 192.0.1.254 > 192.0.2.254: ICMP echo request, id 1892, seq 1, length 64
s/[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]* IP /IP /g
s/, id [0-9]*, seq/, id XXXX, seq/g

# new output from tcpdump-4.9.3-1.fc30.x86_64, really looks like a
# stray debug line

/dropped privs to tcpdump/d

#ESP(spi=0xfd9b5931,seq=0x1), length 288
s/spi=0x[0-9a-f][0-9a-f]*\(,seq=0x[0-9a-f][0-9a-f]*), length\) [0-9]*$/spi=0xSPISPI\1 XXX/
#next lines comes from console, only on kvm and not on namespace
/device eth[0-1] entered promiscuous mode/d
/tcpdump: listening on eth[0-1], link-type/d
