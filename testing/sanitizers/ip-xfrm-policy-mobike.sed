# this is an optional sanitizer in addition to guest-ip-xfrm-*.sed
# which is always run
# aggressively sanitize "ip xfrm policy" for mobike tests
#
/ spi 0x[^ ]* /d
/ reqid [1-9][0-9]* /d
/src 0.0.0.0\/0 dst 0.0.0.0\/0/D
/src ::\/0 dst ::\/0/D
/socket \(in\|out\) priority 0 ptype main/D
