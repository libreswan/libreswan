#!/bin/sh

# script to try combinations of workers and prefixes

grep ^kvmplutotest testing/pluto/TESTLIST \
    | head -100 > testing/pluto/SHORTLIST

for workers in 1 2 3 4 5; do
    p=""
    for prefix in a. b. c. d. e.; do
	p="$p $prefix"
	log="w=${workers}-p=$(echo $p | wc -w).log"
	echo $log
	if test ! -r $log ; then
	    make 2>&1 kvm-install kvm-test \
		      KVM_WORKERS=${workers} \
		      "KVM_PREFIX=${p}" \
		      KVM_TESTS=testing/pluto/SHORTLIST \
		| tee $log
	fi
    done
done
