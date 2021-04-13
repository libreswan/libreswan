# this should not match anything
grep v2N_INVALID_MESSAGE_ID /tmp/pluto.log
# this shows we returned the error in IKE_AUTH
grep "exchange type:" /tmp/pluto.log
