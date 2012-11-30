
if [ -z "$LIBRESWANSRCDIR" ]
then
	if [ -f ../../Makefile.inc ]
	then
	  LIBRESWANSRCDIR=`cd ../.. && pwd`
	else 
	  if [ -f ../../../Makefile.inc ]
	  then 
	    LIBRESWANSRCDIR=`cd ../../.. && pwd`
	  fi
        fi  	
fi

if [ ! -f $LIBRESWANSRCDIR/Makefile.inc ]
then
	echo Makefile.inc not found at LIBRESWANSRCDIR=$LIBRESWANSRCDIR.
	echo Is LIBRESWANSRCDIR set correctly'?'
	exit 5
fi

TESTINGROOT=${LIBRESWANSRCDIR}/testing
UTILS=`cd ${TESTINGROOT}/utils && pwd`

REGRESSRESULTS=${REGRESSRESULTS-results}
MAKE_INSTALL_TEST_DEBUG=${MAKE_INSTALL_TEST_DEBUG-false}
RPM_INSTALL_TEST_DEBUG=${RPM_INSTALL_TEST_DEBUG-false}
FIXUPDIR=`cd ${LIBRESWANSRCDIR}/testing/packaging/fixups && pwd`

# kernel source for local UML, configured, against which one can
# build modules.
KERNEL_LINUSuml_SRC=${POOLSPACE}/plain${KERNVER} export KERNEL_LINUSUML_SRC


