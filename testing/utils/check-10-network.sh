#!/bin/sh

basedir=testing/pluto/$(basename $0 .sh)
hosts="east west rise set"
oss="netbsd freebsd openbsd fedora"

# where am I
if test ! testing/pluto ; then
    echo confused $basedir
    exit 1
fi

for os in ${oss} ; do

    dir=${basedir}-${os}
    echo ${dir}

    mkdir -p ${dir}

    cat <<EOF > ${dir}/description.txt
test network connectivity between the ${os} domains RISE and SET

... along with the generic EAST and WEST domains

this test was generated by $0
EOF

    for h in ${hosts} ; do
	touch ${dir}/${host}.console.txt
    done

    # start again
    rm -f ${dir}/*.sh

    n=1
    case $os in
	netbsd )  eth=vioif ; ifconfig=ifconfig ;;
	openbsd ) eth=vio   ; ifconfig=ifconfig ;;
	freebsd ) eth=vtnet ; ifconfig=ifconfig ;;
	* )       eth=eth   ; ifconfig="ip link set" ;;
    esac

    n=1

    # bring up all the networks

    # bring up all the networks
    for h in east west ; do
	cat <<EOF > ${dir}/0${n}-${h}-ifconfig.sh
../../guestbin/ip.sh addr show eth0
../../guestbin/ip.sh link set eth0 up
../../guestbin/ip.sh addr show eth1
../../guestbin/ip.sh link set eth1 up
EOF
	n=$((n + 1))
    done

    for h in rise set ; do
	cat <<EOF > ${dir}/0${n}-${os}${h}-ifconfig.sh
${ifconfig} ${eth}1
${ifconfig} ${eth}1 up
${ifconfig} ${eth}2
${ifconfig} ${eth}2 up
EOF
	n=$((n + 1))
    done

    # check connectivity

    cat <<EOF > ${dir}/0${n}-${os}rise-ping.sh
../../guestbin/ping-once.sh --up 198.18.1.145 # SET
../../guestbin/ping-once.sh --up 192.0.2.254  # EAST
EOF
    n=$((n + 1))

    cat <<EOF > ${dir}/0${n}-${os}set-ping.sh
../../guestbin/ping-once.sh --up 198.18.1.123 # RISE
../../guestbin/ping-once.sh --up 192.0.1.254  # WEST
EOF
    n=$((n + 1))

done
