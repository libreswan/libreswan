/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

RUN() { echo " $@" 1>&2 ; "$@" ; }
add() { name=$1 ; expr "${name}" : '.*=$' && shift ; RUN ipsec addconn --name ${name} left=192.1.2.45 right=192.1.2.23 "$@" ; }

add send-supported-auth-methods=
add send-supported-auth-methods=yes
add send-supported-auth-methods=no

ipsec connectionstatus | sed -n -e 's/^\("send-supported-auth-methods[^:]*:\) .* \(send-supported-auth-methods:[^;]*;\).*$/\1 \2/p'
