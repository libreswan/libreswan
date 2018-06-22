#!/bin/bash

COUNT=0
while ((COUNT += 1)) ; [ ${COUNT} -lt 10 ] ; do

    R1=$(( ( RANDOM % 32 )  + 1 ))
    R2=$(( ( RANDOM % 32 )  + 1 ))
    R3=$(( ( RANDOM % 32 )  + 1 ))
    R4=$(( ( RANDOM % 32 )  + 1 ))
    echo "COUNT=$COUNT R1=${R1} R2=${R2} R3=${R3} R4=${R4}"

    #EXTRA="--aggressive"
    EXTRA=""

    ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(1=$R1,2=$R2,3=$R3,4=$R4)" 192.1.2.23
    ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(2=$R2,3=$R3,4=$R4)" 192.1.2.23
    ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(1=$R1,3=$R3,4=$R4)" 192.1.2.23
    ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(1=$R1,2=$R2,4=$R4)" 192.1.2.23
    ike-scan $EXTRA --nodns -v --retry 1 --showbackoff --backoff=1 --interval=10  --trans="(1=$R1,2=$R2,3=$R3)" 192.1.2.23
done
