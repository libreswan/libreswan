#!/bin/sh
set -eu
#
# host comments execute using ${IP}
# guest commands execute using ${NSENTER} <full namespace name>
# this script create mount, net, uts namespce with the same name
# one namespace per host.
#

verbose=${verbose-''}

if [ "${verbose}" = "yes" ]; then
	set -x
fi

function err() {
	local exitcode=$1
	shift
	echo "ERROR: $@" >&2
	exit $exitcode
}
usage() {
	echo "usage\n"
}

function info() {
    if [[ -n "${verbose}" ]]; then
        echo "# $@"
    fi
}

OPTIONS=$(getopt -o hgvs: --long verbose,add,cleanup,del,dryrun,del,guest:,host-tweaks,help,restart,src-dir:,testname: -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"

while true; do
	case "$1" in
		-h | --help )
			usage
			exit 0
			shift
			;;

		-g | --guest )
			guest=$2
			info "guest name ${guest}"
			shift 2
			;;
		--host-tweaks )
			hosttweaks=yes
			shift
			;;
		-d | --src-dir )
			srcdir=$2
			if [ -d "${srcdir}" ]; then err 2 "no source directory ${srcdir}"; fi
			shift 2
			;;
		--testname )
			testname="$2"
			shift 2
			;;

		--add )
			cmd="add"
			info "action add"
			shift
			;;

		--del )
			cmd="del"
			info "action del"
			shift
			;;

		--restart )
			cmd="restart"
			info "action del + add"
			shift
			;;

		--verbose )
			verbose="yes"
			set -x
			shift
			;;
		-- ) shift; break ;;

	* )
            shift
            break
            ;;
	esac
done

guest=${guest-west}
testname=${testname-"ikev2-34-lxc"}
srcdir=${srcdir-"/home/build/libreswan"}
cmd=${cmd-add}

ns="${guest}-${testname}"
# short hash 8 char, predictable, unique if names
#tcsm=$(sum <<< "${testname}" | cut -f 1 -d ' ')
tcsm=$(python -c "import binascii; from sys import argv; print(str(binascii.crc_hqx(str.encode(argv[1]), 0)))" ${testname})
breth0=brswan01-${tcsm} #host side bridge for eth0
heth0=h${guest}e0${tcsm} #host eth0 veth end point
heth1=h${guest}e1${tcsm} #host eth1
geth0=g${guest}e0${tcsm} #guest eth0 veth end point
geth1=g${guest}e1${tcsm} #guest eth1 veth end point
breth1=brswan12-${tcsm} #host side bridge for east-west
#unshare --mount=/run/mountns/${ns} --net=/run/netns/${ns} --uts=/run/utsns/${ns} /usr/bin/true
nsargs="--mount=/run/mountns/${ns} --net=/run/netns/${ns} --uts=/run/utsns/${ns}"
NSENTER="/usr/bin/nsenter ${nsargs} "
hosttweaks=${hosttweaks-no}
IP=ip
route1=''
route2=''
route3=''
routedef="route add default via 192.1.2.254"

if [ "${guest}" = "west" ]; then
	eth0ip="192.0.1.254/24"
	eth1ip="192.1.2.45/24"
	gw="192.1.2.254"
	route1='route add 192.0.2.0/24 via 192.1.2.23'
elif [ "${guest}" = "east" ]; then
	eth0ip="192.0.2.254/24"
	eth1ip="192.1.2.23/24"
	gw="192.1.2.254"
	breth0=brswan02-${tcsm} #northnet bridge
	route1='route add 192.0.1.0/24 via 192.1.2.45 '
elif [ "${guest}" = "north" ]; then
	eth0ip="192.0.3.254/24"
	eth1ip="192.1.3.33/24"
	gw="192.1.3.254"
	breth1=brswan13-${tcsm} #north/road-nic bridge
	breth0=brswan03-${tcsm} #northnet bridge
	routedef="route add default via 192.1.3.254"
elif [ "${guest}" = "road" ]; then
	eth0ip="192.1.3.209/24"
	gw="192.1.3.254"
	eth1ip=""
	breth0=brswan13-${tcsm} #north/road-nic bridge
	breth1=""
	heth1=""
	routedef="route add default via 192.1.3.254"
elif [ "${guest}" = "nic" ]; then
	eth0ip="192.1.2.254/24"
	eth1ip="192.1.3.254/24"
	breth0=brswan12-${tcsm} #northnet bridge
	breth1=brswan13-${tcsm} #north/road-nic bridge
	route1='route add 192.0.1.0/24 via 192.1.2.45 '
	route2='route add 192.0.2.0/24 via 192.1.2.23 '
	# route2='route add 192.0.3.0/24 via 192.1.3.33 ' missing kvm. first add there fix test ref output
	routedef=''
fi

ip_link_add() {
	local hif=$1
	local gif=$2
	local gin=$3
	local ipa=$4
	local br=$5

	BRIDGE=$(${IP} -o link show dev ${br}) 2>/dev/null || echo ""
	HIF=$(${IP} -o link show ${hif}) 2>/dev/null || echo ""

	if [ -z "${BRIDGE}" ]; then ${IP} lin add ${br} type bridge; fi
	echo ${BRIDGE} | grep "state UP " || ${IP} link set ${br} up

	${IP} link add name ${hif} mtu 1500 type veth peer name ${gif} mtu 1500
	${IP} link set ${hif} master ${br}
	${IP} link set ${hif} up
	${IP} link set ${gif} netns ${ns}
	${IP} link set dev ${hif} master ${br}

	#execute inside namespace
	${NSENTER} ${IP} link set lo up
	${NSENTER} ${IP} link set ${gif} name ${gin}
	${NSENTER} ${IP} -4 addr add ${ipa} dev ${gin}
	${NSENTER} ${IP} -4 link set ${gin} up
}

ip_link_del()
{
	local hif=$1
	local gif=$2
	local gin=$3
	local ipa=$4
	local br=$5

	${IP} link show ${hif} && ${IP} link set ${hif} down && ${IP} link del name ${hif} || true
	${IP} link show  type veth | grep "master ${br}" && (${IP} link set $br down && ${IP} link del ${br})

}

cleanup()
{
	local ns=$1

	ip_link_del ${heth0} ${geth0} "eth0" ${eth0ip} ${breth0}
	if [ -n "${heth1}" ]; then ip_link_del ${heth1} ${geth1} "eth1" ${eth1ip} ${breth1}; fi
	# ${IP} netns | grep ${ns} && ${IP} netns del ${ns} || true
	for d in /run/netns /run/mountns /run/utsns; do
		grep "nsfs ${d}/${ns}" /proc/mounts && umount ${d}/${ns} && rm -fr ${d}/${ns}
	done
}

add_ns()
{
	for d in /run/netns /run/mountns /run/utsns; do
		if [ -d ${d} ]; then
			echo "${d} exist"
		else
			mkdir -p ${d}
			if [ "${d}" = "/run/mountns" ]; then
				# mountns need special bid on some systems
				# https://github.com/karelzak/util-linux/issues/289
				mount --bind ${d} ${d}
				mount --make-private ${d}
			fi
		fi
		mount | grep "${d}/${ns}" && info 4 "${d}/${ns} is already mounted?"
		test -f "${d}/${ns}" || touch "${d}/${ns}"
	done
	#unshare --mount=/run/mountns/${ns} --net=/run/netns/${ns} --uts=/run/utsns/${ns} /usr/bin/true
	unshare ${nsargs} /usr/bin/hostname ${guest}
	sleep 1
}

prepare_mount()
{
	td=/testing/pluto/${testname}
	nsdir="NS/${ns}"
	rm -rf ${etcns}
	mkdir -p ${etcns}

	ipsecconf="ipsec.conf" #swan-prep will copy over the right one.
	ipsecsecrets="ipsec.secrets" #swan-prep will copy over the right one.
	ipsecd="ipsec.d" #swan-prep will copy over the right one.
	touch "${etcns}/${ipsecconf}"
	touch "${etcns}/${ipsecsecrets}"
	mkdir "${etcns}/${ipsecd}"

	rundir="/run/pluto/${ns}"
	mkdir -p "${rundir}"
	rm -fr "${rundir}"/*

	tmpdir="/tmp/${ns}"
	mkdir -p ${tmpdir}
	rm -fr ${tmpdir}/*
}

host_tweaks ()
{

	#  both all and default versions of the following

	sysctl -w net.ipv4.conf.all.rp_filter=0
	sysctl -w net.ipv4.conf.all.forwarding=1
	sysctl -w net.ipv4.conf.all.proxy_arp=1
	sysctl -w net.ipv4.conf.all.proxy_arp=1
	sysctl -w net.ipv4.conf.default.rp_filter=0
	sysctl -w net.ipv4.conf.default.forwarding=1
	sysctl -w net.ipv4.conf.default.proxy_arp=1
	sysctl -w net.ipv4.conf.default.proxy_arp=1

	# https://wiki.libvirt.org/page/Net.bridge.bridge-nf-call_and_sysctl.conf
	sysctl -w net.bridge.bridge-nf-call-arptables=0
	sysctl -w net.bridge.bridge-nf-call-iptables=0
	sysctl -w net.bridge.bridge-nf-call-ip6tables=0

	echo "done host tweaks";
}

if [ "${hosttweaks}" = "yes" ]; then
	host_tweaks;
fi

if [ "${cmd}" = "del" -o "${cmd}" = "restart" ]; then
	cleanup ${ns} && echo "cleaned up ${ns}"
	if [ "${cmd}" = "del" ]; then
		exit 0;
	fi
fi

#prepare_mount
# ${IP} netns add "${ns}" # is not good enough.
add_ns ${ns}
${NSENTER} ${IP} addr add 127.0.0.1/8 dev lo
ip_link_add ${heth0} ${geth0} "eth0" ${eth0ip} ${breth0}
if [ -n "${heth1}" ]; then ip_link_add ${heth1} ${geth1} "eth1" ${eth1ip} ${breth1}; fi
if [ -n "${route1}" ]; then ${NSENTER} ${IP} ${route1}; fi
if [ -n "${route2}" ]; then ${NSENTER} ${IP} ${route2}; fi
if [ -n "${routedef}" ]; then ${NSENTER} ${IP} ${routedef}; fi
echo "done creating network interfaces"
#${IP} netns
${NSENTER} /usr/bin/hostname ${guest}
