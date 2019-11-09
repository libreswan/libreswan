#!/bin/sh

DIAG_OUT_FILE=OUTPUT/restart_diag.txt
DIAG_SUM_FILE=OUTPUT/restart_sum.txt

iMax=${1-1000}
collect_diag () {
	echo "=== start of diagnostics ==="
	ipsec whack --trafficstatus >> $DIAG_OUT_FILE
	ipsec status >> $DIAG_OUT_FILE
	ip xfrm policy >> $DIAG_OUT_FILE
	ip xfrm state >> $DIAG_OUT_FILE
	ping -q -n -c 4 -I 192.0.1.254 192.0.2.254 2>&1 >> $DIAG_OUT_FILE
	ipsec whack --trafficstatus >> $DIAG_OUT_FILE
	echo "=== end of diagnostics ==="
}

set_output_file()
{
	type=$1
	DATE=`date +"%Y%m%d%H%M%S"`
	DIAG_OUT_FILE="OUTPUT/restart_$type_$DATE.txt"
}

hit_double_sa ()
{
	i=$1
	M="=== Attempt $i hit multiple SA collecting dignostics  ==="
	set_output_file("multiple")
	echo "$M" >>  $DIAG_SUM_FILE
	echo "$M" >>  $DIAG_OUT_FILE
	collect_diag
}

hit_bug ()
{
	i=$1
	M="=== Attempt $i hit the but collecting dignostics for analaysis ==="
	set_output_file("bug")
	echo "$M" >>  $DIAG_OUT_FILE
	echo "$M" >>  $DIAG_SUM_FILE
	collect_diag
	exit 1
}

echo "Start restart test max $iMax"
for ((i = 1; i < $iMax; i++));
	do
	ipsec restart;
	echo "Restart attempt $i/$iMax"
	ping -q -n -c 4 -I 192.0.1.254 192.0.2.254 2>&1 > /dev/null || hit_bug $i;
	SA_COUNT=`ipsec whack --trafficstatus |wc -l`
	if [ "$SA_COUNT" -gt "1" ]; then
		# interesting case to diagnose
		hit_double_sa $i
	fi
done;
echo done
