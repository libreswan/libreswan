# should be gone
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
grep '^connection from' /tmp/pluto.log | grep -v EAGAIN
eagain=$(grep EAGAIN /tmp/pluto.log | wc -l) ; test ${eagain} -gt 30 && echo "${eagain} is too much EAGAIN?"
