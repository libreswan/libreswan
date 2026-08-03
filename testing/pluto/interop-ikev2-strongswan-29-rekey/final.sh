ipsec _kernel state
ipsec _kernel policy
if test -r /tmp/charon.log ; then strongswan status ; fi
if test -r /tmp/pluto.log ; then ipsec connectionstatus ; fi
