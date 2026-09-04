#/bin/sh

{
    ls -F1 ..
} | {
    sed -n -e 's;/;;p'
} | {
    while read d ; do
	if grep '^[a-z][a-z]*[ 	]*'"${d}"'[^a-z0-9-]' ../TESTLIST > /dev/null ; then
	    :
	elif test -r ../$d/description.txt ; then
	    echo $d
	fi
    done
}
