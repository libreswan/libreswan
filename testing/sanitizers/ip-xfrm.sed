# XXX: can this optional sanitizer be merged into guest-ip*.sed which
# is always run

# this an aggressive sanitizer for "ip xfrm state" esp
# careful when mxixing this with "ipsec look"
# "ipsec look" sanitizer are similar

# Paul: this is _crazy_, nothing is ephemeral here so it completely breaks
#       everything that tries to use this. It seems like it tried to fixup
#       older kernel vs newer kernel ip xfrm output or something ????
/src 0.0.0.0\/0 dst 0.0.0.0\/0/d
/socket \(in\|out\) priority 0 ptype main/d
/src ::\/0 dst ::\/0/d
/replay-window /d
/auth-trunc hmac/d
/^\tencap type espinudp sport/d
/proto esp reqid/d
s/aead rfc4106(gcm(aes)) .* \([0-9 ]*\)/aead rfc4106(gcm(aes)) KEY \1/
s/proto esp spi 0x.* reqid/proto esp spi 0xSPISPI reqid/g
