# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

if test $# -gt 0 ; then
    d=$1
else
    d=$(basename $(pwd))
fi

case $d in
    *ikev1*) ikev2=no ;;
    *ikev2*) ikev2=yes ;;
esac

ike=$(echo $d | sed -n -e 's/-esp-.*//' -e 's/-ah-//' -e 's/.*-ikev[0-9]*-\(.*\)/\1/p')

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
	ike=${ike}
	phase2=${phase2}
	phase2alg=${phase2alg}
	also=base
EOF
