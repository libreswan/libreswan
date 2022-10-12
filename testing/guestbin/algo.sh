# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

if test $# -gt 0 ; then
    d=$1
    install=false
else
    d=$(basename $(pwd))
    install=true
fi

case $d in
    *ikev1*) ikev2=no ;;
    *ikev2*) ikev2=yes ;;
esac

ike=$(echo $d | sed -n -e 's/-esp-.*//' -e 's/-ah-//' -e 's/.*-ikev[0-9]*-\(.*\)/\1/p')

phase2=
phase2alg=
case $d in
    *-esp-*)
	phase2=esp
	phase2alg=$(echo $d | sed -n -e 's/.*-esp-\(.*\)/\1/p')
	;;
    *-ah-*)
	phase2=ah
	phase2alg=$(echo $d | sed -n -e 's/.*-ah-\(.*\)/\1/p')
	;;
esac

if ${install} ; then
    ../../guestbin/swan-prep
fi

echo /etc/ipsec.conf ...

{
    cat <<EOF
config setup
	# put the logs in /tmp for the UMLs, so that we can operate
	# without syslogd, which seems to break on UMLs
	logfile=/tmp/pluto.log
	logtime=no
	logappend=no
	dumpdir=/tmp
	plutodebug=all
conn base
	left=192.1.2.45
	leftid=@west
	leftsubnet=192.0.1.0/24
	right=192.1.2.23
	rightid=@east
	rightsubnet=192.0.2.0/24
	authby=secret
conn algo
	ikev2=${ikev2}
	$(test -n "${ike}" || echo '#')ike=${ike}
	$(test -n "${phase2}" || echo '#')phase2=${phase2}
	$(test -n "${phase2alg}" || echo '#')phase2alg=${phase2alg}
	also=base
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
    ipsec start
    ../../guestbin/wait-until-pluto-started
    ipsec auto --add algo
fi
