# These are caused by a leaking file descriptor causing a false positive
#
/^type=AVC .* avc:  denied .* comm="ip".*$/d
/^type=SYSCALL .* comm="ip" exe="\/usr\/sbin\/ip" .*$/d
