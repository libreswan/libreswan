send() { printf "$@" | ncat east 4500 ; }
# open the TCP socket
send ''
# open the TCP socket, send one byte
send '\0'
# open the TCP socket, send not IKETCP
send '123456'
# open the TCP socket, send IKETCP
send 'IKETCP'
# open the TCP socket, send IKETCP<byte>
send 'IKETCP\0'
# open the TCP socket, send IKETCP<0x0000>
send 'IKETCP\x0\x0'
# open the TCP socket, send IKETCP<0x00ff>
send 'IKETCP\x0\xff'
# open the TCP socket, send IKETCP<0xffff>
send 'IKETCP\xff\xff'
