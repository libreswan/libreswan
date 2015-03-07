
if [ -z "${LIBRESWANSRCDIR}" ]; then
    if [ -f ../../kvmsetup.sh ]; then
	LIBRESWANSRCDIR=$(cd ../.. && pwd)
    else
	if [ -f ../../../kvmsetup.sh ]; then
	    LIBRESWANSRCDIR=$(cd ../../.. && pwd)
	fi
    fi  	
fi

if [ ! -f ${LIBRESWANSRCDIR}/kvmsetup.sh ]; then
	echo "kvmsetup.sh not found at LIBRESWANSRCDIR=${LIBRESWANSRCDIR}/."
	echo "Is LIBRESWANSRCDIR set correctly?"
	exit 5
fi

LIBRESWANSRCDIR=$(cd ${LIBRESWANSRCDIR}; pwd)
export LIBRESWANSRCDIR

TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=$(cd ${TESTINGROOT}/utils && pwd)
KLIPSTOP=${LIBRESWANSRCDIR}/linux
FIXUPDIR=$(cd ${LIBRESWANSRCDIR}/testing/sanitizers && pwd)
CONSOLEDIFFDEBUG=${CONSOLEDIFFDEBUG:-false}

# find this on the path if not already set.
TCPDUMP=${TCPDUMP:-tcpdump}

REGRESSRESULTS=${REGRESSRESULTS:-results}

