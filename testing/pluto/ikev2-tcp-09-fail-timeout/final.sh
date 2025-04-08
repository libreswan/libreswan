# should be gone
ipsec _kernel state
ipsec _kernel policy
grep '^connection from' /tmp/pluto.log | grep -v EAGAIN
eagain=$(grep EAGAIN /tmp/pluto.log | wc -l) ; test ${eagain} -gt 30 && echo "${eagain} is too much EAGAIN?"
