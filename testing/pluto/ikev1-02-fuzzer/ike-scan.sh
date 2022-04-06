#!/bin/bash

# https://datatracker.ietf.org/doc/html/rfc2409#page-33

for AUTH in 3=1 3=3 3=1,3=3 3=$(( ( RANDOM % 32 )  + 1 ))
do
    COUNT=0
    while ((COUNT += 1)) ; [ ${COUNT} -lt 5 ] ; do

	ENCR=1=$(( ( RANDOM % 32 )  + 1 ))
	HASH=2=$(( ( RANDOM % 32 )  + 1 ))
	GROUP=4=$(( ( RANDOM % 32 )  + 1 ))
	echo "COUNT=$COUNT ${AUTH} ${ENCR} ${HASH} ${GROUP}"

	#EXTRA="--aggressive"
	EXTRA=""

	ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(${ENCR},${HASH},${AUTH},${GROUP})" 192.1.2.23
	ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(${HASH},${AUTH},${GROUP})" 192.1.2.23
	ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(${ENCR},${AUTH},${GROUP})" 192.1.2.23
	ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(${ENCR},${HASH},${GROUP})" 192.1.2.23
	ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(${ENCR},${HASH},${AUTH})" 192.1.2.23
    done
done
