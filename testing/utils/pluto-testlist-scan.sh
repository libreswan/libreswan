
# pluto-testlist-scan.sh: a hack to analyze the results of Pluto tests
#
# Synopsis:
#	cd testing/pluto
#	../utils/pluto-testlist-scan.sh
# The result is, for each test, a one-line report on the latest result.
# The set of tests is specified by testing/pluto/TESTLIST.
#
# Bonus: the flag --re-sanitize will run ../../utils/re-sanitize.sh
# for each test (but the output will clutter the report).
#
# Copyright 2014 D. Hugh Redelmeier

set -ue

# capture path to my script as anchor for $me.dumb-cert-fragment
me=`readlink -f $0`

cd ~/libreswan/testing/pluto

export preprocess=""

previous=""

commontest() {
	testtype="$1"
	testname="$2"
	teststatus="$3"
	notes=""

	if [ ! -d "$testname/OUTPUT" ] ; then
		notes="$notes,NO-OUTPUT"
	else
		(
			cd $testname
			$preprocess
		)
	fi

	if [ -f "$testname/OUTPUT/RESULT" ] ; then
		if [ -n "previous" -a "$testname/OUTPUT/RESULT" -ot "$previous" ] ; then
			ls -ld "$testname/OUTPUT/RESULT"
		fi
		previous="$testname/OUTPUT/RESULT"
	fi

	for i in "$testname"/OUTPUT/core* ; do
		if [ -f "$i" ] ; then
			notes="$notes,`basename $i`"
		fi
	done

	for i in "$testname"/OUTPUT/*.pluto.log ; do
		if [ -f "$i" ] ; then
			if fgrep 'ASSERTION FAILED' "$i" >/dev/null ; then
				notes="$notes,ASSERT:`basename $i`"
			fi
			if fgrep 'EXPECTATION FAILED' "$i" >/dev/null ; then
				notes="$notes,EXPECT:`basename $i`"
			fi
			if fgrep 'SEGFAULT' "$i" >/dev/null ; then
				notes="$notes,SEGFAULT:`basename $i`"
			fi
		fi
	done

	if [ ! -f "$testname/OUTPUT/RESULT" ] ; then
		result=none
	elif grep '"result":"passed"' "$testname/OUTPUT/RESULT" >/dev/null ; then
		result=good
	elif grep '"result":"failed"' "$testname/OUTPUT/RESULT" >/dev/null ; then
		result=bad
		for i in west east north road ; do
			if [ ! -f "$testname/OUTPUT/$i.console.diff" ] ; then
				# not even there
				:
			elif [ ! -s "$testname/OUTPUT/$i.console.diff" ] ; then
				notes="$notes,$i:ok"
			elif [ ! -s "$testname/$i.console.txt" ] ; then
				notes="$notes,$i:missing-baseline"
			else
				# something is in $testname/OUTPUT/$i.console.diff
				if egrep '^[+-]' "$testname/OUTPUT/$i.console.diff" | egrep -v '^(\+\+\+|---)' | LC_ALL=C sort -u | cmp -s - "$me.dumb-cert-fragment" ; then
					notes="$notes,$i:mainca-noise"
				elif ! grep -v 'No test for authenc(' "$testname/OUTPUT/$i.console.diff" | egrep -v '^(\+\+\+|---)' | egrep '^[-+]' >/dev/null ; then
					notes="$notes,$i:authenc-noise"
				else
					notes="$notes,$i:bad"
				fi
			fi
		done
	else
		result=dunno
	fi
	if [ "$teststatus" = "$result" ] ; then
		show=""
	else
		show="!=$result"
	fi
	echo "$testtype	$testname	$teststatus$show$notes"
}

ctltest() {
	testname="$1"
	teststatus="$2"
	commontest "${FUNCNAME[0]}" $testname $teststatus
}

kvmplutotest() {
	testname="$1"
	teststatus="$2"
	commontest "${FUNCNAME[0]}" $testname $teststatus
}

skiptest() {
	testname="$1"
	teststatus="$2"
	commontest "${FUNCNAME[0]}" $testname $teststatus
}

umlplutotest() {
	testname="$1"
	teststatus="$2"
}

umlXhost() {
	testname="$1"
	teststatus="$2"
}

for arg ; do
	case "$arg" in
	--re-sanitize)
		preprocess="../../utils/re-sanitize.sh"
		;;
	*)
		echo "$me: unexpected operand: $arg" >&2
		exit 1
		;;
	esac
done

. ./TESTLIST
