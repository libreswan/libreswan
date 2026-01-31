#!/bin/sh

cd $(dirname $0)

hostname=east
prefix=OUTPUT/${hostname}
breakpoints=${prefix}.breakpoints.log

{
    cat OUTPUT/${hostname}.gdb.log
} | {
    sed \
	-e '/^thread / s/ *#0 */ /' \
	-e '/^thread / s/ \([a-z0-9_A-Z][^ ]*\) *(lock=\(0x[0-9a-z]*\).*/ \2 \1/' \
	-e '/^#[1-9][0-9]*/ s/ *0x[0-9a-z]* *in / /' \
	-e '/^#[1-9][0-9]*/ s/ *\([a-z0-9_A-Z][^ ]*\) (.*/ \1/'
} | {
    sed -z -e 's/\n#[1-9][0-9]* / /g'
} > ${breakpoints}

for thread in 1 2 ; do
    sed -n -e '/^thread '"${thread}"' / s/.* \(0x[0-9a-f]*\).*/\1/p' < ${breakpoints} | sort -u > ${prefix}.thread.${thread}.locks
done

grep '^thread 1 .* NSC_DeriveKey .* ikev2_derive_child_keys' ${breakpoints} | while read thread nr lock xxx ; do
    grep "^thread 2 ${lock} " ${breakpoints}
done > ${prefix}.ikev2_derive_child_keys.locks
