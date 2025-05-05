/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add send-vendorid=
ipsec add send-vendorid=yes
ipsec add send-vendorid=no

ipsec connectionstatus | sed -n -e 's/^\([^:]*:\) .* \(send-vendorid:[^;]*;\).*$/\1 \2/p'
