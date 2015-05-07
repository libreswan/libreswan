
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

FIXUPDIR=$(cd ${LIBRESWANSRCDIR}/testing/crypto/fixups && pwd)
TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=$(cd ${TESTINGROOT}/utils && pwd)
TESTSUBDIR=crypto

