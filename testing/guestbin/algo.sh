# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

if test $# -eq 0 ; then
    echo "usage: $0 addconn-param" 1>&2
    exit 1
fi

RUN() {
    echo " $@"
    "$@"
}

RUN ipsec start
../../guestbin/wait-until-pluto-started
RUN ipsec addconn --name algo \
    authby=secret \
    leftid=@west \
    rightid=@east \
    left=192.1.2.45 \
    right=192.1.2.23 \
    leftsubnet=192.0.1.0/24 \
    rightsubnet=192.0.2.0/24 \
    "$@"
RUN ipsec up algo
RUN ../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
RUN ipsec stop
