#!/bin/sh

USER=build export USER

. /etc/profile

# make sure that $HOME/bin/touch is before /bin/touch.
PATH=$HOME/bin:$PATH export PATH

# source it so that we get the settings for $TODAY
source $HOME/freeswan-regress-env.sh

regress_branch() {
	env
	starttime=`date`
	source $HOME/bin/regress-nightly.sh
	regressstat=$?
	endtime=`date`

	STATUSDIR=$REGRESSTREE/$BRANCH/$TODAY
	echo "<LI> <A HREF=\"$TODAY/testresults.html\">$TODAY</A></LI>" >>$REGRESSTREE/$BRANCH/index.html

	mkdir -p $STATUSDIR

	cp $BUILDSPOOL/stdout.txt $STATUSDIR
	cp $BUILDSPOOL/stderr.txt $STATUSDIR

	(cd $REGRESSTREE/$BRANCH && rm -f lastgood && ln -s $TODAY lastgood)

	(
	echo "From: Nightly Build process <build@abigail.freeswan.org>"
	echo "To: $NIGHTLY_WATCHERS"
	echo "Subject: FreeS/WAN build for $BRANCH $TODAY"
	echo
	echo "Please see "
	echo "http://private.abigail.freeswan.org/freeswan/$BRANCH/$TODAY/testresults.html "
	echo "or"
	echo "http://bugs.freeswan.org:81/regress/$BRANCH/$TODAY/testresults.html "
	echo "for more details."
        echo
        echo "Tests started at $starttime"
        echo "        ended at $endtime"
        echo
	if [ $regressstat -ne 0 ]
	then
		echo;
		echo "The build failed: $regressstat"
		echo;
		exit 1
	fi
	
	echo
	links -dump $STATUSDIR/testresults.html

	echo "Output from failing tests (up to $FAILLINES lines)"

	cd $STATUSDIR
	if [ -f faillist.txt ]
	then
		cat faillist.txt | while read testname
		do
			for diff in $testname/OUTPUT/*.diff
			do
				echo 
				echo "===== $diff:"
				cat $diff
			done
		done | sed "${FAILLINES}q"
	fi

	) | teammail.sh

	$HOME/bin/regresschart.sh $REGRESSTREE/$BRANCH 
}

( regress_branch )

#BRANCH=PRE1_97 export BRANCH
#
#( regress_branch )

