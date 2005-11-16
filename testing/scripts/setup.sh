
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

TESTINGROOT=${OPENSWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`
FIXUPDIR=`cd ${OPENSWANSRCDIR}/testing/klips/fixups && pwd`
NJ=${UTILS}/uml_netjig/uml_netjig

REGRESSRESULTS=${REGRESSRESULTS-results}



