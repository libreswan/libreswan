# the sleep is to keep the pipe open, something better?
send() { { printf "$@" ; for c in 1 2 3 4 5 6 7 8 9 10 ; do sleep 1 ; printf "" ; done; } | ncat east 4500 ; }

# 4.  TCP-Encapsulated Stream Prefix
#
#  0      1      2      3      4      5
# +------+------+------+------+------+------+
# | 0x49 | 0x4b | 0x45 | 0x54 | 0x43 | 0x50 |
# +------+------+------+------+------+------+
#
# followed by ...
#
# 3.1.  TCP-Encapsulated IKE Header Format
#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |            Length             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Non-ESP Marker                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                      IKE header [RFC7296]                     ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# ... where LENGTH includes the length field

# open the TCP socket
send ''

# send one byte
send 'I'

# send not IKETCP
send '123456'

# send IKETCP prefix
send 'IKETCP'

# send IKETCP prefix + <00>
send 'IKETCP\00'

# send IKETCP prefix + length=0; min length is 2
send 'IKETCP\x0\x0'

# send IKETCP prefix + length=2
send 'IKETCP\x0\x2'

# send IKETCP prefix + length=6 + non-ESP marker (0)
send 'IKETCP\x00\x06''\x00\x00\x00\x00'

# send IKETCP prefix + length=6 + non-ESP marker (0) + <ff> == mangled
send 'IKETCP\x00\x07''\x00\x00\x00\x00''\xff'

# send IKETCP prefix + length=2+4+28=0x22 + non-ESP marker (0) + <header:length=28=0x1c>
send 'IKETCP\x00\x22''\x00\x00\x00\x00''\x01\x02\x03\x04\x05\x06\x07\x08''\x00\x00\x00\x00\x00\x00\x00\x00''\x00\x20\x22\x08''\x00\x00\x00\x00''\x00\x00\x00\x1c' | hexdump

# send IKETCP prefix + length=0x00ff
# for some reason this sometimes causes EAGAIN on east
send 'IKETCP\x00\xff'

# send IKETCP prefix + length=0xffff
send 'IKETCP\xff\xff'
