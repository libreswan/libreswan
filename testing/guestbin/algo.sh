# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

RUN() {
    echo "begin #"
    echo " $@"
    "$@"
    echo "end #"
}

if test $# -gt 0 ; then
    d=$1
    install=false
else
    d=$(basename $(pwd))
    install=true
fi

case $d in
    *ikev1*) keyexchange=ikev1 ; ikev1_policy=accept ;;
    *ikev2*) keyexchange=ikev2 ; ikev1_policy=drop   ;;
esac

ike=$(echo $d | sed -n -e 's/-esp.*//' -e 's/-ah.*//' -e 's/.*-ikev[0-9]*-\(.*\)/\1/p')

phase2=
case $d in
    *-esp*) phase2=esp ;;
    *-ah*) phase2=ah ;;
esac

phase2alg=
case $d in
    *-esp-*) phase2alg=$(echo $d | sed -n -e 's/.*-esp-\(.*\)/\1/p') ;;
    *-ah-*) phase2alg=$(echo $d | sed -n -e 's/.*-ah-\(.*\)/\1/p') ;;
esac

type= # aka mode
case $d in
    *transport*) type=transport ;;
    *tunnel*) type=tunnel ;;
esac

compress= # aka mode
case $d in
    *ipcomp*) compress=yes ;;
esac

left=
right=
case $d in
    *ipv6* | *4in6* | *6in6* )
	left=2001:db8:1:2::45
	right=2001:db8:1:2::23
	;;
    *ipv4* | *6in4* | *4in4* | * )
	left=192.1.2.45
	right=192.1.2.23
	;;
esac

leftsubnet=
rightsubnet=
case $d in
    *ipv6* | *6in4* | *6in6* )
	leftsubnet=2001:db8:0:1::/64
	rightsubnet=2001:db8:0:2::/64
	;;
    *ipv4* | *4in6* | *4in4* | * )
	leftsubnet=192.0.1.0/24
	rightsubnet=192.0.2.0/24
	;;
esac

if ${install} ; then
    rm -rf /etc/ipsec.d/*
fi

echo /etc/ipsec.conf ...

{
    cat <<EOF
config setup
	ikev1-policy=${ikev1_policy}
	# put the logs in /tmp for the UMLs, so that we can operate
	# without syslogd, which seems to break on UMLs
	logfile=/tmp/pluto.log
	logtime=no
	logappend=no
	dumpdir=/tmp
	plutodebug=all
conn algo
	# IKE
	keyexchange=${keyexchange}
	$(test -n "${ike}" || echo '#')ike=${ike}
	left=${left}
	right=${right}
	authby=secret
	leftid=@west
	rightid=@east
	# CHILD
	leftsubnet=${leftsubnet}
	rightsubnet=${rightsubnet}
	$(test -n "${phase2}" || echo '#')phase2=${phase2}
	$(test -n "${phase2alg}" || echo '#')phase2alg=${phase2alg}
	$(test -n "${type}" || echo '#')type=${type}
	$(test -n "${compress}" || echo '#')compress=${compress}
EOF
} | {
    if ${install} ; then
	tee /etc/ipsec.conf
    else
	cat
    fi
}

echo /etc/ipsec.d/ipsec.secrets ...

{
    cat <<EOF
@west @east : PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
EOF

} | {
    if ${install} ; then
	tee /etc/ipsec.d/ipsec.secrets
    else
	cat
    fi
}

echo starting pluto ...

if ${install} ; then
    RUN ipsec start
    ../../guestbin/wait-until-pluto-started
    RUN ipsec add algo
fi
