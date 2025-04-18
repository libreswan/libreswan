# match tcpdump.sh

/guestbin\/tcpdump.sh/,/^[a-z][a-z]* #$/ {

  /dropped privs to tcpdump/ { N ; s/^.*\n// }

  # reading from file /tmp/east.ikev2-xfrmi-02-responder.tcpdump.pcap, link-type EN10MB (Ethernet), snapshot length 262144
  /reading from file .*tcpdump.pcap/ s/, snapshot length [0-9]*$//

  # nflog
  # 15:49:06.782887 IP 192.0.1.254 > 192.0.2.254: ICMP echo request, id 1892, seq 1, length 64
  s/[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]* IP /IP /g
  s/, id [0-9]*, seq/, id XXXX, seq/g

  # new output from tcpdump-4.9.3-1.fc30.x86_64, really looks like a
  # stray debug line

  #ESP(spi=0xfd9b5931,seq=0x1), length 288
  s/spi=0x[0-9a-f][0-9a-f]*\(,seq=0x[0-9a-f][0-9a-f]*), length\) [0-9]*$/spi=0xSPISPI\1 XXX/

  #next lines comes from console, only on kvm and not on namespace
  /tcpdump: listening on eth[0-1], link-type/d

}
