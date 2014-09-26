# this is not included in the default filter set
#14:52:30.705781 IP 127.0.0.1 > 127.0.0.1: ESP(spi=0xd201e25e,seq=0x1), length 116
s/^.*\(IP 127.0.0.1 > 127.0.0.1: ESP(spi=0x\)[0-9a-f]*\(,seq=0x\)[0-9]*\(.*length \)[0-9].*$/\1SPISPI\2X\3XXX/
# filter out the backgrounding of tcpdump
# tcpdump -i lo -n -c 6 2> /dev/null &
# [1] 1652
/^ tcpdump .*\&/ {N; s/^ nc \(.*\&\)\n\[[0-9]*\] [0-9]*$/ tcpdump \1 /g}
