ipsec _kernel state
ipsec _kernel policy
if test -r /run/strongswan/charon.ctl ; then strongswan status ; fi
if test -r /run/pluto/pluto.ctl ; then ipsec connectionstatus ; fi
