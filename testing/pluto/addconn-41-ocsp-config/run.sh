#!/bin/sh

RUN()
{
    echo " $@"
    "$@"
}

RUN ipsec pluto --config $1 --leak-detective
RUN ../../guestbin/wait-until-pluto-started
RUN grep '^[^|].*OCSP' /tmp/pluto.log
RUN ipsec whack --shutdown
RUN cp /tmp/pluto.log OUTPUT/$(basename $1 .conf).log
