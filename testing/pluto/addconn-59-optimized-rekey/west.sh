/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

RUN() { echo " $@" 1>&2 ; "$@" ; }
add() { name=$1 ; expr "${name}" : '.*=$' && shift ; RUN ipsec addconn --name ${name} left=192.1.2.45 right=192.1.2.23 "$@" ; }

# unset, yes and no are accepted
add optimized-rekey=
add optimized-rekey=yes
add optimized-rekey=no
# anything else is rejected
add optimized-rekey=maybe
