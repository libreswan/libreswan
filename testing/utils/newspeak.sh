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
	sed -i -e 's/ipsec auto --/ipsec /' $f
	sed -i -e 's/ipsec whack --trafficstatus/ipsec trafficstatus/' $f
	# this is a common idiom from code predating connectionstatus
	sed -i -e 's/ipsec status *| *grep /ipsec connectionstatus /' $f
    done
done

cat <<EOF

YOU MUST RUN:

  ./kvm install modified check

EOF
