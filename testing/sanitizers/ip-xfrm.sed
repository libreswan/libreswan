# XXX: can this optional sanitizer be merged into guest-ip*.sed which
# is always run

# this an aggressive sanitizer for "ip xfrm state" esp
# careful when mxixing this with "ipsec look"
# "ipsec look" sanitizer are similar
/src 0.0.0.0\/0 dst 0.0.0.0\/0/d
/socket \(in\|out\) priority 0 ptype main/d
/src ::\/0 dst ::\/0/d
/replay-window /d
/auth-trunc hmac/d
/^\tencap type espinudp sport/d
/proto esp reqid/d
s/proto comp spi 0x[^ ]* /proto comp spi 0xSPISPI /
s/proto esp spi 0x[^ ]* /proto esp spi 0xSPISPI /
