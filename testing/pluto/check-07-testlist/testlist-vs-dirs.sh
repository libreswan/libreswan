#!/bin/sh

{
    awk '/^[a-z]/ { print $2 ; }' ../TESTLIST
} | {
    while read d; do
	if test ! -r ../$d/description.txt ; then
	    echo $d ;
	fi
    done
}
