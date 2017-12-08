# this an aggressive sanitizer for "ip xfrm state" esp
# carefull when mxixing this with "ipsec look"
# "ipsec look" sanitizer are similar
/src 0.0.0.0\/0 dst 0.0.0.0\/0/d
/socket \(in\|out\) priority 0 ptype main/d
/src ::\/0 dst ::\/0/d
s/^\tproto esp spi 0x[^ ]* reqid [0-9]*/\tproto esp spi 0xSPISPIXX reqid REQID/g
/replay-window /d
/auth-trunc hmac/d
s/^\tenc \(.*\) \(0x.*\)/\tenc \1 0xKEY/g
s/^\taead \(.*\) \(0x.*\)/\taead \1 0xKEY/g
/^\tencap type espinudp sport/d
/proto esp reqid/d
