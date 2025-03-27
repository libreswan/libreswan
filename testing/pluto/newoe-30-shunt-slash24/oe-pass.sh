# start
./oe.sh "$@"

RUN() {
    echo :
    echo " $@"
    "$@"
    echo :
}

# should establish; and packets flow
RUN ../../guestbin/wait-for.sh --match '#2' -- ipsec trafficstatus
RUN ../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
RUN ../../guestbin/ipsec-kernel-policy.sh
RUN ipsec trafficstatus
RUN ipsec shuntstatus

