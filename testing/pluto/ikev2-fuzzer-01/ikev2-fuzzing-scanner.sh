#!/bin/bash -eu
#
# this is a fuzzer/scanner that sends random IKE_INIT(IKEv2) messages to pluto
# In the IKE message header the following fields are valid -
#  iCookie, rCookie, Major Minor version, flags and IKE message length.
# The rest of the message is random bytes.
# These random payloads, bytes, should  not crash pluto.
# Copyright (C) 2020-21 Antony Antony <antony@phenome.org>

# echo $SUDO_COMMAND
trap 'catch $? $LINENO' EXIT

IP=127.0.0.1
count=0
count_max=${count_max=0}
if [ "$count_max" -gt "0" ]; then
	count=1
	echo "$0 run $count_max times"
else
	echo "$0 run in infinite loop"
fi

verbose=${verbose-''}
max_len=${max_len-10000} #max ike message length

if [ "${verbose}" = "yes" ]; then
	set -x
fi

if [ -f /run/pluto/pluto.pid ] ; then
	kill -9 $(cat /run/pluto/pluto.pid) 2>/dev/null > /dev/null || echo ""
	rm -fr /run/pluto/pluto.pid || echo ""
	sleep 1
fi
echo "" > /tmp/pluto.log
# the following payloads are from a pluto log
spi_i="cf03939d5a085245"
spi_r="0000000000000000"
verse="21202208"
msg_i="00000000"
len1=$((8+8+4+4+4))
prefix="${spi_i}${spi_r}${verse}${msg_i}"
string=""
RESULT=""
pl=""

# Wrap the command in begin#/end# markers that the sanitizer will
# recognize a command between prompts, that way the command's output
# will be sanitized.

RUN() {
    echo "begin #"
    echo " $@"
    "$@"
    echo "end #"
}

random_len() {
	FLOOR=30;
	CEILING=${max_len};
	RANGE=$(($CEILING-$FLOOR+1));
	RESULT=$RANDOM;
	let "RESULT %= $RANGE";
	RESULT=$(($RESULT+$FLOOR));
}

catch() {
	ecode=$1
	lno=$2
	set +e +u
	if [ "$1" != "0" ]; then
		echo "caught error trap $lno"
		# error handling goes here
		NEW_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		ofile="OUTPUT/crasher-${NEW_UUID}.txt"
		dfile="OUTPUT/info-${NEW_UUID}.txt"

		echo "# ecode $ecode LINENO $lno" >> ${ofile}
		echo "echo ${pl} | xxd -r -p | nc -u $IP 500 " >> ${ofile}

		echo "# len $RESULT" >> ${dfile}
		pidof pluto | grep $plutopid >>  ${dfile}
		ipsec status >> ${dfile}
		echo "#dmesg " >> ${dfile}
		dmesg >> ${dfile}

		cp /tmp/pluto.log OUTPUT/pluto-${NEW_UUID}.log
	fi
	set -eu
}

while [ "${count}" = "0" -o "${count}" -lt "${count_max}" ]
do
	if [ "${count}" -gt "0" ]; then
		count=$((count+1))
	fi
	echo "" > /tmp/pluto.log
	RUN ipsec start
	../../guestbin/wait-until-pluto-started
	plutopid=$(cat /run/pluto/pluto.pid)
	RUN ipsec add test
	if [ $? != 0 ] ; then
		continue
	fi
	random_len
	len=$(($len1+$RESULT))
	size=$(printf "%08x" $len)
	string=$(openssl rand -hex ${RESULT})
	pl="${prefix}${size}${string}"
	echo "${pl}" | xxd -r -p | nc -u $IP 500 || echo "expect error"
	(pidof pluto | grep ${plutopid} > /dev/null) || echo "pluto crashed?"
	ipsec status 2>/dev/null > /dev/null
	RUN ipsec stop
	# grep "bytes from" /tmp/pluto.log
	# grep "sending" /tmp/pluto.log || echo ""
	sleep 1
done

echo "ran $count times"
