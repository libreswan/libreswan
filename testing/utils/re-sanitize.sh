#!/bin/bash
. ../../../kvmsetup.sh
if [ -f ./testparams.sh ] ; then
	. ./testparams.sh
else
	. ../../default-testparams.sh
fi
. ../setup.sh
. ../../utils/functions.sh

failure=0

for host in $LIBRESWANHOSTS
do
   if [ -f "${host}.console.txt" ]
   then
	#echo "re-sanitizing ${host}"
	# sanitize last run
	if [ -f OUTPUT/${host}.console.verbose.txt ]
	then
		cleanups="cat OUTPUT/${host}.console.verbose.txt "
		for fixup in `echo $REF_CONSOLE_FIXUPS`
		do

			if [ -f $FIXUPDIR/$fixup ]
			then
				case $fixup in
				*.sed) cleanups="$cleanups | sed -f $FIXUPDIR/$fixup";;
				*.pl)  cleanups="$cleanups | perl $FIXUPDIR/$fixup";;
				*.awk) cleanups="$cleanups | awk -f $FIXUPDIR/$fixup";;
				*) echo Unknown fixup type: $fixup;;
				esac
			elif [ -f $FIXUPDIR2/$fixup ]
			then
				case $fixup in
				*.sed) cleanups="$cleanups | sed -f $FIXUPDIR2/$fixup";;
				*.pl)  cleanups="$cleanups | perl $FIXUPDIR2/$fixup";;
				*.awk) cleanups="$cleanups | awk -f $FIXUPDIR2/$fixup";;
				*) echo Unknown fixup type: $fixup;;
				esac
			else
				echo Fixup $fixup not found.
				return
			fi
		done

		fixedoutput=OUTPUT/${host}.console.txt
		rm -f $fixedoutput OUTPUT/${host}.console.diff
		## debug echo $cleanups
		eval $cleanups >$fixedoutput
		# stick terminating newline in for fun.
		echo >>$fixedoutput
		if diff -N -u -w -b -B ${host}.console.txt $fixedoutput >OUTPUT/${host}.console.diff
		then
			echo "# ${host}Console output matched"
		else
			echo "# ${host}Console output differed"
			failure=1
		fi
		if [ -f OUTPUT/${host}.console.diff -a \! -s OUTPUT/${host}.console.diff ]
		then
			rm OUTPUT/${host}.console.diff
		fi
	fi
   fi
done

if [ $failure -eq 0 ]
then
	echo "$(basename $(pwd)): passed"
else
	echo "$(basename $(pwd)): FAILED"
fi

