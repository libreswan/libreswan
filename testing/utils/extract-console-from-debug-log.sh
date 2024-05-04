#!/bin/sh

if test $# -ne 2; then
    cat <<EOF
Usage:

  $0 <debug.log> <host>

Grub through <debug.log> extracting the console messages for <host>.
Specifically the boot messages.  For instance:

  $0 testing/pluto/basic-pluto-01/OUTPUT/debug.log east

(this script extracts the text by grubbing for low-level debug-log
message)

EOF
    exit 1
fi

debug=$1 ; shift
host=$1 ; shift

{
    cat ${debug}
} | {
    # extract the text read from the host's console
    sed -n \
	-e 's/^DEBUG .* '"${host}"' .*: read <<b.\(.*\)[^>]>>>*$/\1/p' \
	-e 's/^DEBUG .* '"${host}"' .*: send <<b.\(.*\)[^>]>>>*$/\1/p'
} | {
    # turn the text into a single very long line (the true \r\n were
    # escaped).
    tr -d '\n'
} | {
    # convert the escaped \r and \n into line breaks
    sed -e 's/\\r\\r\\n/\n/g' -e 's/\\r\\n/\n/g' -e 's/\\n/\n/g'
} | {
    # strip out magic escape characters used to fancy print on the
    # console (can this just be disabled).  Apparently \u2026 is
    # horizontal ellipsis.
    sed -e 's/\\x1b\[0;1;3[0-9]m//g' \
	-e 's/\\x1b\[0;3[0-9]m//g' \
	-e 's/\\x1b\[0m//g' \
	-e 's/\\x1bM\\r\\x1b\[K//' \
	-e 's/\\u2026/.../'
}
