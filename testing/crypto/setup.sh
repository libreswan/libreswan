
if [ -z "$OPENSWANSRCDIR" ]
then
	if [ -f ../../umlsetup.sh ]
	then
	  OPENSWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../umlsetup.sh ]
	  then 
	    OPENSWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $OPENSWANSRCDIR/umlsetup.sh ]
then
	echo Umlsetup not found at OPENSWANSRCDIR=$OPENSWANSRCDIR.
	echo Is OPENSWANSRCDIR set correctly'?'
	exit 5
fi

OPENSWANSRCDIR=`cd ${OPENSWANSRCDIR}; pwd`
export OPENSWANSRCDIR

FIXUPDIR=`cd ${OPENSWANSRCDIR}/testing/crypto/fixups && pwd`
TESTINGROOT=${OPENSWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`
TESTSUBDIR=crypto



