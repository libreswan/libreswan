/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn-clones=no
ipsec add addconn-clones=yes
ipsec add addconn-clones=0
ipsec add addconn-clones=1

ipsec connectionstatus | sed -n -e 's/^\([^:]*:\) .* \(clones: [^;]*;\).*/\1 \2/p'
