# On east this shows the duplicates on west there is nothing.
sed -n -e '/; retransmitting response/p' -e 's/\(; message dropped\).*/\1/p' /tmp/pluto.log

ipsec _kernel state
ipsec _kernel policy
