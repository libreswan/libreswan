#!/bin/sh

# script to try combinations of workers and prefixes

grep ^kvmplutotest testing/pluto/TESTLIST \
    | head -100 > testing/pluto/SHORTLIST

for workers in 1 2 3 4 5 ; do
    p=""
    for prefix in a. b. c. d. e. ; do
	p="$p $prefix"
	log="w=${workers}-p=$(echo $p | wc -w).log"
	if test ! -r $log ; then
	    make 2>&1 kvm-install kvm-test \
		      KVM_WORKERS=${workers} \
		      "KVM_PREFIX=${p}" \
		      KVM_TESTS=testing/pluto/SHORTLIST \
		| tee $log
	fi
    done
done

fields() {
    failed=$(awk '/ failed: / { f=$4 } END { print f }' < $log)
    start=$(awk '/run started at/ { print $NF }' < $log)
    time=$(awk '/run finished at/ { print $NF }' < $log)
    minutes=$(awk '/run finished at/ {
       n = split($NF,t,":")
       s = 0
       for (i = 1; i < n; i++) {
         s = s * 60 + t[i]
       }
       print s
    }' < $log)
}

workers() {
    ls *.log | sed -e 's/.*w=\([0-9]\).*/\1/'  | sort -n -u
}
prefixes() {
    ls *.log | sed -e 's/.*p=\([0-9]\).*/\1/'  | sort -n -u
}


echo "Parallel Reboots vs Parallel Tests: Failures"
printf "Parallel Reboots"
for prefix in $(prefixes) ; do
    printf ",$prefix Tests"
done
printf "\n"
for worker in $(workers) ; do
    printf $worker
    for log in *w=$worker*.log ; do
	fields
	printf ,$failed
    done
    printf '\n'
done

echo "Parallel Tests vs Parallel Reboots: Failures"
printf "Parallel Tests"
for worker in $(workers) ; do
    printf ",$worker Reboots"
done
printf "\n"
for prefix in $(prefixes) ; do
    printf $prefix
    for log in *p=$prefix*.log ; do
	fields
	printf ,$failed
    done
    printf '\n'
done

echo "Parallel Reboots vs Parallel Tests: Time"
printf "Parallel Reboots"
for prefix in $(prefixes) ; do
    printf ",$prefix Tests"
done
printf "\n"
for worker in $(workers) ; do
    printf $worker
    for log in *w=$worker*.log ; do
	fields
	printf ,$minutes
    done
    printf '\n'
done

echo "Parallel Tests vs Parallel Reboots: Time"
printf "Parallel Tests"
for worker in $(workers) ; do
    printf ",$worker Reboots"
done
printf "\n"
for prefix in $(prefixes) ; do
    printf $prefix
    for log in *p=$prefix*.log ; do
	fields
	printf ,$minutes
    done
    printf '\n'
done
