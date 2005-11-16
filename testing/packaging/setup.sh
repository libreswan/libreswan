
if [ -z "$OPENSWANSRCDIR" ]
then
	if [ -f ../../Makefile.inc ]
	then
	  OPENSWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../Makefile.inc ]
	  then 
	    OPENSWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $OPENSWANSRCDIR/Makefile.inc ]
then
	echo Umlsetup not found at OPENSWANSRCDIR=$OPENSWANSRCDIR.
	echo Is OPENSWANSRCDIR set correctly'?'
	exit 5
fi

TESTINGROOT=${OPENSWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`

REGRESSRESULTS=${REGRESSRESULTS-results}
MAKE_INSTALL_TEST_DEBUG=${MAKE_INSTALL_TEST_DEBUG-false}
RPM_INSTALL_TEST_DEBUG=${RPM_INSTALL_TEST_DEBUG-false}
FIXUPDIR=`cd ${OPENSWANSRCDIR}/testing/packaging/fixups && pwd`

# kernel source for local UML, configured, against which one can
# build modules.
KERNEL_LINUSuml_SRC=${POOLSPACE}/plain${KERNVER} export KERNEL_LINUSUML_SRC


