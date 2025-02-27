# this is an optional sanitizer in addition to guest-ip-xfrm-*.sed
# which is always run
# aggressively sanitize "ip xfrm state" for mobike tests
/replay-window /d
/auth-trunc hmac/d
/proto esp reqid/d
/enc cbc(aes)/d
/aead rfc4106(gcm(aes))/d
# used NATED6501 for now. there could be a better word
# first ip address port 4500 3503-3509 -> 3501
s/\(s\|d\)port 35[0-9][0-9] /sport NATED3501 /
#first IP address port 500
s/\(s\|d\)port 25[0-9][0-9] /sport NATED2501 /
# second ip address port 4500 6503-6509 -> 6501
s/\(s\|d\)port 65[0-9][0-9] /sport NATED6501 /
#second IP address port 500
s/\(s\|d\)port 55[0-9][0-9] /sport NATED5501 /
