# this is an optional sanitizer in addition to guest-ip-xfrm-*.sed
# which is always run
# aggressivly sanitize "ip xfrm state" for mobike tests
/replay-window /d
/auth-trunc hmac/d
/proto esp reqid/d
/enc cbc(aes)/d
/aead rfc4106(gcm(aes))/d
