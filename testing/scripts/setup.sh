# this script gets invoked in arbitrary sub-directories in testing.
# Figure out which one it is.

if [ -z "${LIBRESWANSRCDIR}" ]; then
    for d in ../.. ../../.. ; do
	if test -f $d/testing/scripts/setup.sh ; then
	    LIBRESWANSRCDIR=$d
	    break
	fi
    done
fi

if [ ! -f ${LIBRESWANSRCDIR}/testing/scripts/setup.sh ]; then
    echo "invalid LIBRESWANSRCDIR=${LIBRESWANSRCDIR}."
    exit 5
fi

LIBRESWANSRCDIR=$(cd ${LIBRESWANSRCDIR}; pwd)
export LIBRESWANSRCDIR

FIXUPDIR=$(cd ${LIBRESWANSRCDIR}/testing/scripts/fixups && pwd)
FIXUPDIR2=$(cd ${LIBRESWANSRCDIR}/testing/sanitizers && pwd)
TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=$(cd ${TESTINGROOT}/utils && pwd)

TESTSUBDIR=scripts
