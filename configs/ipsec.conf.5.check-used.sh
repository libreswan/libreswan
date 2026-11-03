#!/bin/sh

# Check all conn and setup entries appear somewhere in the
# documentation.

configs=$(dirname $0)
top=$(dirname $(realpath ${configs}))

for conf in setup conn ; do
    for x in ${configs}/d.ipsec.conf/${conf}/*.xml ; do
	b=$(basename ${x} .xml)
	f=d.ipsec.conf/${conf}/${b}.xml
	e=${conf}.${b}

	use=$(grep '&'${e}';' ${configs}/ipsec.conf.5.xml ${configs}/d.ipsec.conf/sect/*.xml | head -1)
	if test -z "${use}" ; then
	    echo '&'${e}';' is not used
	    exit 1
	fi

	if ! grep "id='${conf}.${b}'" ${x} > /dev/null ; then
	    echo anchor "id='${conf}.${b}'" missing
	    exit 1
	fi

    done
done
