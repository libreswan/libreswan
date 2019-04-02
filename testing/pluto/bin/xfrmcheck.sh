#!/bin/sh
#
# prefix with ERROR so it becomes clear it is not "normal" output.

OUT=$(grep -v -P "\t0$" /proc/net/xfrm_stat | sed "s/^/ERROR:  /")
if [ -n "$OUT" ];
then
	echo $OUT
	exit 1
fi
exit 0
