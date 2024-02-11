/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# sourceip is shown as {my,their}_ip=
add() { ipsec auto --add $1 ; ipsec whack --connectionstatus --name $1 | grep _ip= ; }

# fails because there's no subnet=

add sourceip-without-selector
add sourceips-without-selector

# fails because sourceip is not within subnet
add sourceip-outside-selector

# fails because sourceip is not within subnet
add sourceips-outside-selectors

# all good
add sourceip-inside-selector
add sourceips-inside-selectors

# subnets= tests can't check inside/outside
add sourceip-outside-subnets
add sourceip-inside-subnets
add sourceips-inside-subnets

add sourceip-vs-interface-ip
