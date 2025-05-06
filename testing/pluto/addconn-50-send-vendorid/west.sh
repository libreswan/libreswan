/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

RUN() { echo " $@" 1>&2 ; "$@" ; }
add() { name=$1 ; expr "${name}" : '.*=$' && shift ; RUN ipsec addconn --name ${name} left=192.1.2.45 right=192.1.2.23 "$@" ; }

add send-vendorid=
add send-vendorid=yes
add send-vendorid=no

add cisco-unity=
add cisco-unity=yes
add cisco-unity=no

add fake-strongswan=
add fake-strongswan=yes
add fake-strongswan=no

ipsec connectionstatus | sed -n -e 's/^\("send-vendorid[^:]*:\) .* \(send-vendorid:[^;]*;\).*$/\1 \2/p'
ipsec connectionstatus | sed -n -e 's/^\("cisco-unity[^:]*:\) .* \(cisco-unity:[^;]*;\).*$/\1 \2/p'
ipsec connectionstatus | sed -n -e 's/^\("fake-strongswan[^:]*:\) .* \(fake-strongswan:[^;]*;\).*$/\1 \2/p'
