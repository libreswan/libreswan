#!/bin/sh

# mangle param into connection name

name=$(echo "$@" | sed \
		       -e 's/ /-/g' \
		       -e 's/%//g' \
		       -e 's/=192[^ ]*/=ipv4/g' \
		       -e 's/=2001[^ ]*/=ipv6/g' \
		       -e 's/leftnexthop=//g' \
		       -e 's/rightnexthop=//g' \
		       -e 's/left=//' \
		       -e 's/right=//' \
		       -e 's/hostaddrfamily=/hostaddrfamily-/'
    )

echo " ipsec add ${name}"
if ipsec addconn --name ${name} "$@" ; then

    echo 'road #'
    echo " ipsec connectionstatus ${name} | grep ' host: '"
    ipsec connectionstatus ${name} | grep ' host:'
    ipsec delete ${name}

else

    # there should be no output
    ipsec connectionstatus ${name} | grep ' host:'

fi
