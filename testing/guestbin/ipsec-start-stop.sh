#!/bin/sh

conn=$1 ; shift

RUN()
{
    echo + "$@"
    "$@"
}

RUN ipsec start
$(dirname $0)/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival

RUN ipsec add ${conn}
RUN ipsec up ${conn}

RUN ipsec stop
