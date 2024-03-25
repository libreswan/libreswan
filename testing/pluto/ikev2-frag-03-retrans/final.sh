# On east this shows the duplicates on west there is nothing.
sed -n -e '/; retransmitting response/p' -e 's/\(; message dropped\).*/\1/p' /tmp/pluto.log

../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
