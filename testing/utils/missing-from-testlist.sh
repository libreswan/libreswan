#!/bin/sh

# hack to print the test directories that don't appear in TESTLIST.

nf=18
df=10

{
    # use anything kvm things is a test directory
    ./testing/utils/kvmresults.py testing/pluto/*/ \
	--skip '' \
	--print test-name
} | {
    # filter out any in TESTLIST
    while read t ; do
	grep "[^a-z0-9]$t[^-a-z0-9]" testing/pluto/TESTLIST > /dev/null || echo $t
    done
} | {
    # agument each test with author et.al.
    while read t ; do
	h=$(git log --format="%h" testing/pluto/$t | tail -1)
	d=$(git log --date=short --format="%ad" $h -- testing/pluto/$t)
	n=$(git log --format="%an" $h -- testing/pluto/$t)
	echo ${n}:${d}:${h}:${t}
    done
} | {
    # sort by name then date
    sort -t : -k 1,1 -k 2,2V
} | {
    # pretty print
    IFS=:
    pn=
    while read n d h t ; do
	if test "${pn}" != "${n}" ; then
	    echo
	    echo "$n"
	    echo
	    pn=${n}
	fi
	echo ${d} ${h} ${t}
    done
}
