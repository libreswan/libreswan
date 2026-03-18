#!/bin/sh

set -e

RUN() {
    # echo "" "$@"
    "$@"
}

RUN rsync -ap /testing/baseconfigs/all/etc/nsd/conf.d   /etc/nsd
RUN rsync -ap /testing/baseconfigs/all/etc/nsd/server.d /etc/nsd
RUN sed -i 's/port: 53$/port: 5353/' /etc/nsd/server.d/nsd-server-libreswan.conf
if test -n "${SWAN_PLUTOTEST}" ; then
    RUN /testing/guestbin/nsd-start.sh start
else
    RUN systemctl start nsd
fi

RUN rsync -ap /testing/baseconfigs/all/etc/unbound /etc/
if test -n "${SWAN_PLUTOTEST}" ; then
    RUN ../../guestbin/unbound-start.sh restart
else
    RUN systemctl start unbound
fi
