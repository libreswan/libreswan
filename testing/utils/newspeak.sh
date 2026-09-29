#!/bin/sh

if test "$#" -eq 0 ; then
    cat <<EOF
Usage:

  $0 <directory> ...

Try to convert test stripts and expected output to new command syntax.

  YOU MUST RUN THE TESETSUITE AFTER THIS!

EOF
fi

for d in "$@" ; do
    for f in  $d/*.sh $d/*.txt ; do
	echo $f
	# drop the auto/whack prefix
	sed -i \
	    -e 's/ipsec auto --/ipsec /' \
	    -e 's/ipsec whack --trafficstatus/ipsec trafficstatus/' \
	    -e 's/ipsec whack --shuntstatus/ipsec shuntstatus/' \
	    $f
	# this is a common idiom from scripts that predate
	# connectionstatus
	sed -i -e 's/ipsec status *| *grep \([-a-z0-9]*\)$/ipsec connectionstatus \1/' $f
	# migrate some strongswan commands
	sed -i \
	    -e 's/strongswan up \([-a-z0-9]*\)$/swanctl --initiate --child \1 --loglevel 0/' \
	    -e 's/strongswan down \([-a-z0-9]*\)$/swanctl --terminate --ike \1 --loglevel 0/' \
	    $f
    done
    for f in $d/*.conf ; do
	case $f in
	    *swan* ) continue ;;
	esac
	echo $f
	sed -i -e '/nexthop=/d' $f
    done
done

cat <<EOF

YOU MUST RUN:

  ./kvm install modified check

EOF
