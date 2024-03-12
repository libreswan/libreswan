# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage:

  $0 <dir> ...

where the <dir> name is used to generate the test:

  <os(west)>-<os(east)>

	interop from <os(west)> to <os(east)); possible OSs are
	freebsd, netbsd, fedora, openbsd, debian, alpine, linux (aka
	east, west)

	default is linux

  strongswan|iked|racoon

	interop using the specified daemon; iked implies os=openbsd
	and racoon implies os=netbsd; hence iked-racoon interops from
	openbsd(west) to netbsd(east)

	default is libreswan

  ikev1|ikev2

  	force IKE version

  transport|tunnel

        propose transport (or tunnel)

  ipcomp

	propose ipcomp

  ike|esp|ah

	force interop to use the specified ike/esp/ah algorithm; for
	instance ike=aes_gcm or ah-sha2

  ipv4|ipv6|4in4|4in6|6in4|6in6

        force interop to use the INNERinOUTER protocols; default is IPv4

EOF
    exit 1
fi

emit() {
    echo
    echo "===> $1"
    echo
    tee $p/$1
}

i=0
script() {
    i=$(expr $i + 1)
    local n=$(printf "%02d-%s" $i $1)
    emit ${n}
}

for d in "$@" ; do

    p=$(realpath ${d})
    t=$(basename ${d})

    rm -vf ${p}/*.sh ${p}/*.conf ${p}/*.secrets

    i=0
    e=
    w=
    type='#type='
    compress='#compress='
    keyexchange='#keyexchange='
    ikev1_policy='#ikev1_policy'
    phase2='#phase2='
    ike='#ike='
    p2=
    p2a=
    k=
    daemon=libreswan

    for h in $(echo ${t} | tr '-' ' ') ; do
	case ${h} in

	    interop ) ;;

	    freebsd|netbsd|fedora|openbsd|debian|alpine) w=${e} ; e=${h} ;;
	    linux) w=${e} ; e= ;;

	    strongswan ) daemon=strongswan ; w=${e} ; e= ;;
	    iked )       daemon=iked       ; w=${e} ; e=openbsd ;;
	    racoon )     daemon=racoon     ; w=${e} ; e=netbsd ;;

	    transport ) type=type=transport ;;
	    tunnel )    type=type=tunnel    ;;

	    ipcomp) compress=compress=yes ;;

	    ikev1 ) k= ; keyexchange=keyexchange=ikev1 ; ikev1_policy=ikev1-policy=accept ;;
	    ikev2 ) k= ; keyexchange=keyexchange=ikev2 ; ikev1_policy=ikev1-policy=drop   ;;

	    ike ) k= ;;
	    esp ) p2=esp ; p2a= ; phase2=phase2=esp ;;
	    ah )  p2=ah  ; p2a= ; phase2=phase2=ah  ;;

	    ipv4 ) inner=ipv4 ; outer=ipv4 ;;
	    ipv6 ) inner=ipv6 ; outer=ipv6 ;;

	    4in4 ) inner=ipv4 ; outer=ipv4 ;;
	    4in6 ) inner=ipv4 ; outer=ipv6 ;;
	    6in4 ) inner=ipv6 ; outer=ipv4 ;;
	    6in6 ) inner=ipv6 ; outer=ipv6 ;;

	    * )
		# need to strip leading -
		if test -n "${p2}" ; then
		    p2a=${p2a}-${h}
		    phase2alg=${p2}=$(expr ${p2a} : '-\(.*\)')
		else
		    k=${k}-${h}
		    ike=ike=$(expr ${k} : '-\(.*\)')
		fi
		;;

	esac
    done

    if test -n "${w}" ; then
	west=${w}w
    else
	west=west
    fi

    if test -n "${e}" ; then
	east=${e}e
    else
	east=east
    fi

    left='#left='
    right='#right='
    case ${outer} in
	ipv6 )   left=left=2001:db8:1:2::45 ; right=right=2001:db8:1:2::23 ;;
	ipv4|* ) left=left=192.1.2.45       ; right=right=192.1.2.23       ;;
    esac

    leftsubnet='#leftsubnet='
    rightsubnet='#rightsubnet='
    case ${inner} in
	ipv4|* ) leftsubnet=leftsubnet=192.0.1.0/24      ; rightsubnet=rightsubnet=192.0.2.0/24      ;;
	ipv6 )   leftsubnet=leftsubnet=2001:db8:0:1::/64 ; rightsubnet=rightsubnet=2001:db8:0:2::/64 ;;
    esac

    swan_prep="swan-prep"
    case ${inner}-in-${outer} in
	ipv4-in-ipv4 ) swan_prep="swan-prep -4" ;;
	ipv6-in-ipv6 ) swan_prep="swan-prep -6" ;;
	ipv4-in-ipv6 ) swan_prep="swan-prep -46" ;;
	ipv6-in-ipv4 ) swan_prep="swan-prep -46" ;;
    esac

    emit <<EOF ipsec.conf
config setup
	# put the logs in /tmp for the UMLs, so that we can operate
	# without syslogd, which seems to break on UMLs
	logfile=/tmp/pluto.log
	logtime=no
	logappend=no
	dumpdir=/tmp
	plutodebug=all
	${ikev1_policy}
conn interop
	# IKE
	${keyexchange}
	${ike}
	${left}
	${right}
	authby=secret
	leftid=@west
	rightid=@east
	# CHILD
	${leftsubnet}
	${rightsubnet}
	${phase2}
	${phase2alg}
	${type}
	${compress}
EOF

    emit <<EOF ipsec.secrets
@east @west : PSK "this is a really really big secret"
EOF

    for init in init-${east}.sh init-${west}.sh ; do
	case ${init} in
	    *bsd*)
		script <<EOF ${init}
../../guestbin/netbsd-prep.sh
EOF
		;;
	    *)
		script <<EOF ${init}
../../guestbin/${swan_prep}
EOF
		;;
	esac
    done

    for start in start-${east}.sh start-${west}.sh ; do
	script <<EOF ${start}
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add interop
EOF
    done

    script <<EOF initiate-${west}.sh
ipsec up interop
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
EOF

    # IKEv1 needs this
    script <<EOF established-${east}
../../guestbin/wait-for.sh --match interop -- ipsec trafficstatus
EOF

    script <<EOF ping-${west}.sh
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
EOF

    for traffic in traffic-${east}.sh traffic-${west}.sh ; do
	script <<EOF ${traffic}
ipsec trafficstatus
EOF
    done

    touch $p/description.txt
    touch $p/${west}.console.txt
    touch $p/${east}.console.txt

done
