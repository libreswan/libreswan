
if [ -z "${LIBRESWANSRCDIR}" ]; then
    echo "LIBRESWANSRCDIR not set" 1>&1
    exit 1
fi
# starts with /? - the pattern match is anchored
if ! expr ${LIBRESWANSRCDIR} : / > /dev/null; then
    echo "${LIBRESWANSRCDIR} needs to be absolute"
    exit 1
fi

TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=${TESTINGROOT}/utils
KLIPSTOP=${LIBRESWANSRCDIR}/linux
FIXUPDIR=${LIBRESWANSRCDIR}/testing/sanitizers
CONSOLEDIFFDEBUG=${CONSOLEDIFFDEBUG:-false}

# find this on the path if not already set.
TCPDUMP=${TCPDUMP:-tcpdump}

REGRESSRESULTS=${REGRESSRESULTS:-results}
