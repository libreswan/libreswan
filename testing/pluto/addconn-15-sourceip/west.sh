/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# sourceip is shown as {my,their}_ip=
add() { ipsec auto --add $1 ; ipsec whack --connectionstatus --name $1 | grep _ip= ; }

# sourceip=;host=;#subnet= ok

add sourceip-inside-host
add sourceip-outside-host

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

add sourceip-inside-subnet-protoport
add sourceip-outside-subnet-protoport
add sourceip-inside-selector-protocol-port
add sourceip-outside-selector-protocol-port

add sourceip-vs-interface-ip

add sourceip-ipv4-ipv6-ipv4
add sourceip-ipv6-ipv4-ipv6
