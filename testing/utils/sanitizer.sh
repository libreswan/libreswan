#!/bin/bash
set -eu

utilsdir=$(dirname $(readlink -f $0))
testingdir=$(dirname $utilsdir)
fixupdir=$testingdir/sanitizers

# cleanup the given console output

if test $# -lt 1; then
    cat <<EOF 1>&2
Usage:

    $0 <console.verbose.txt> [ <test-directory> [ <fixup-directory> ... ] ]

Sanitizes the file <console.verbose.txt> using fixup scripts specified
by testparams.sh (or default-testparams.sh).  The result is written to
STDOUT.

<test-directory>

	The directory containing testparams.sh

	Only required when when the unsanitized file
	<console.verbose.txt> is not under OUTPUT/ in the build tree.

	By default, the test under directory:
		${testingdir}
	from this source tree is used.

<fixup.directory> ...

	A list of directories containing the fixup scripts.

	By default, the directory:
		${fixupdir}
	from this source tree is used.

EOF
    exit 1
fi


# *.console.verbose.txt

if test "x$1" = "x-"; then
    input=- ; shift
else
    input=$(readlink -f $1) ; shift
    if test ! -r "$input"; then
	echo "unsanitized file not found: $input" 1>&2
	exit 1
    fi
    case "$input" in
	*.console.verbose.txt )
	    :
	    ;;
	* )
	    echo "expecting an unsanitized .console.verbose.txt file: $input" 1>&2
	    exit 1
	    ;;
    esac
fi

# <test-directory>

if test $# -gt 0; then
    testdir=$(readlink -f $1) ; shift
elif test "x$input" != "x-" ; then
    testdir=$(dirname $(dirname $input))
else
    echo "No <test-directory> specified (and console is '-')" 1>&2
    exit 1
fi


# <fixups-dir> ...
if test $# -gt 0; then
    fixupdirs="$@"
else
    fixupdirs="${fixupdir}"
fi


# Load REF_CONSOLE_FIXUPS et.al.
if [ -f $testdir/testparams.sh ]; then
    # testparams.sh expects to be sourced from its directory,
    # expecting to be able to include the relative pathed
    # ../../default-testparams.sh
    pushd $testdir > /dev/null
    . ./testparams.sh
    popd > /dev/null
else
    . $testingdir/default-testparams.sh
fi


# The per-host fixup.  Get hostname from the INPUT file name,
# stripping of what is probably .console.verbose.txt
host_fixups=$(basename ${input} | sed -e 's;\..*;;' | tr '[a-z]' '[A-Z]')_CONSOLE_FIXUPS
REF_CONSOLE_FIXUPS=${!host_fixups:-${REF_CONSOLE_FIXUPS}}

if test -z "$REF_CONSOLE_FIXUPS"; then
    echo "\$REF_CONSOLE_FIXUPS empty" 1>&2
    exit 1
fi


cleanups=
sedups=
cleanup=

find_cleanup()
{
    local fixup=$1
    # Parameter list contains fixup directories; find the one
    # containing the sanitizer script ${fixup}
    cleanup=
    for fixupdir in "${fixupdirs}" ; do
	if test -f ${fixupdir}/${fixup} ; then
	    cleanup=$(realpath --relative-to=$PWD ${fixupdir}/${fixup})
	    return
	fi
    done
    echo "fixup '${fixup}' not found in $@" 1>&2
    exit 1
}

cleanup() {
    local fixup=$1 ; shift
    local op="$*" ; shift
    find_cleanup ${fixup}
    if test -z "${cleanups}" -a -z "${sedups}" ; then
	cleanups="${op} < ${input} -f ${cleanup}"
    else
	cleanups="${cleanups}${sedups} | ${op} -f ${cleanup}"
	sedups=
    fi
}

sedup() {
    local fixup=$(basename $1 .sed-f).sed ; shift
    find_cleanup ${fixup}
    if test -z "${cleanups}" -a -z "${sedups}" ; then
	sedups="sed < ${input} -f ${cleanup}"
    elif test -z "${sedups}" ; then
	sedups=" | sed -f ${cleanup}"
    else
	sedups="${sedups} -f ${cleanup}"
    fi
}

for fixup in ${REF_CONSOLE_FIXUPS}; do
    # now add the fixup to the pipeline
    case $fixup in
	*.sed)
	    cleanup ${fixup} sed
	    ;;
	*.awk)
	    cleanup ${fixup} awk
	    ;;
	*.sed-f) # -f sanitizers can be merged
	    sedup ${fixup}
	    ;;
	*)
	    echo "unknown fixup type: $fixup" 1>&2
	    exit 1
	    ;;
    esac
done

# close
cleanups="${cleanups}${sedups}"
# echo "${cleanups}" 1>&2

eval $cleanups
status=$?

exit $status
